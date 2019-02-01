########
# Copyright (c) 2019 Cloudify Platform All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

from cloudify import ctx
from cloudify_rest_client import CloudifyClient
from cloudify import manager
import json
import ldap
from flask import Flask
from threading import Thread
from datetime import datetime
import time
import os
import thread
import uuid
import copy

def start(**kwargs):
    log("Starting LDAP operator")
    ''' Starts the operator process
    '''

    # For DEBUGGING locally
    if ctx._local:
        client = CloudifyClient(
            host = '10.239.2.83',
            username = 'admin',
            password = 'admin',
            tenant = 'default_tenant')
    else:
        client = manager.get_rest_client()

    r,w = os.pipe()
    pid = os.fork()
    if pid > 0:
        # wait for pid on pipe
        os.close(w)
        for i in range(10):
            pid = os.read(r, 10)
            if pid == "":
                time.sleep(1)
                log("waiting for pid")
                continue
            else:
                ctx.instance.runtime_properties["pid"] = str(pid)
                break
        if pid == "":
            log("ERROR: Failed to get child PID")
        os.close(r)
        return

    os.close(r)
    os.chdir("/tmp")
    os.setsid()
    os.umask(0)
    close_fds([w])

    pid = os.fork()
    if pid > 0:
        os.write(w,str(pid))
        os.close(w)
        os._exit(0)
    os.close(w)

    # Needed by Flask
    os.open("/dev/null", os.O_RDONLY)
    os.open("/dev/null", os.O_WRONLY)

    # Start REST server
    app = Flask(__name__)

    # init stats
    stats = {}
    stats['errcnt'] = 0
    stats['actions'] = []

    # init config
    config = {}
    config['log_location'] = '/tmp/log'

    try:
        set_routes(app, ctx.node.properties, stats, config)
        rest = Thread(target=app.run, kwargs={"debug":False})
        rest.start()
    except Exception as e:
        log(str(e))
        os._exit(0)

    # TODO Deep copy of properties to runtime_properties.
    #      To enable changes at runtime
    operate(client, ctx.node.properties, stats)

    os._exit(0)


def stop(**kwargs):
    ''' Stops the operator process
    '''
    pid = ctx.instance.runtime_properties['pid']

    ctx.logger.info("stopping process {}".format(pid))

    res = os.system("kill "+str(pid))
    if res != 0:
        ctx.logger.error("kill failed for pid ".format(pid))


def operate(client, properties, stats):
    action_mgr = ActionQueueManager(stats, log)

    log("INFO: LDAP operator starting")
    # authenticate (simple for now)
    ld = None
    
    # NOTE: LDAP CONNECTION SHOULD TOLERATE INSTABILITY
    try:
        # TODO This should be in a retry loop in case of disconnection
        ld = ldap.initialize(properties['ldap_config']['server_url'])
        ld.simple_bind_s(properties['ldap_config']['user'],
                               properties['ldap_config']['password'])
    except Exception as e:
        stats['errcnt'] += 1
        stats['last_error'] = "ldap connect failed: " + str(e.message)
        log("ERROR: ldap connection failed: {}".format(e.message))

    # main loop

    # NOTE: PERSISTENT SEARCH SHOULD BE USED IF AVAILABLE (TBD)
    # NOTE: SHOULD VALIDATE CONFIGURATION OF RULES BEFORE STARTING

    rule_state = []
    for rule in properties['rules']:
        rule_state.append(RuleProcessStatus(rule))

    while True:
        for rstate in rule_state:
            try:
                if rstate.state == rstate.ST_INITIAL:
                    trigger_rule(action_mgr, ld, rstate, stats)
                else:
                    check_rule(rstate)
            except Exception as e:
                stats['errcnt'] += 1
                stats['last_error'] = e.message
                log("ERROR: caught exception " + e.message)
        time.sleep(3)


def check_rule(rstate):
    ''' Check a rules status '''

    log("INFO: checking rule " + rstate.id)

    if rstate.state == rstate.ST_STARTED:
        log("INFO: rule in progress")
    elif rstate.state == rstate.ST_COMPLETE:
        log("INFO: rule complete")
        # reset to detect next trigger
        rstate.state == rstate.ST_INITIAL
    elif rstate.state == rstate.ST_ERROR:
        # failed, but reset
        rstate.state == rstate.ST_INITIAL
    else:
        log("ERROR: illegal state: " + rstate.state)


def trigger_rule(action_mgr, ld, rstate, stats):
    ''' Starts a rules actions '''

    log("INFO: processing rule")
    rule = rstate.rule

    if rule['type'] == 'attr_scan':
        try:
            res = ld.search_s(rule['key'], ldap.SCOPE_SUBTREE,"objectclass=*")
        except Exception as e:
            stats['errcnt'] += 1
            stats['last_error'] = "ldap search exc=" + str(e.message)
            log("Caught exception in user key search: {}".format(e.message))
            return
        id = process_attr_scan_case(action_mgr, rstate, res, True, stats)
        if not id: 
            return
        rstate.id = id
    else:
        log("ERROR: unknown rule type '{}'".format(rule['type']))


def process_attr_scan_case(action_mgr, rstate, res, pos, stats):
    ''' Searches a collection for an entry with the named
        attribute that matches the condition
    '''
    log("DEBUG: starting attr search")
    rule = rstate.rule
    log("DEBUG: res = " + str(res))
    for entry in res:
        if rule['attribute'] in entry[1]:
            log("DEBUG: attr search triggered ({})".format(
                rule['condition']['type']))
            if rule['condition']['type'] == 'contains':
                if not lastval_from_rstate(rstate,entry[0]) and  (
                    rule['condition']['value'] in entry[1][rule['attribute']]):
                    id = action_mgr.add(rule['actions'])
                    rstate.lastval[entry[0]] = True
                    stats['actions'].append("TRIGGER:"+json.dumps(rstate.rule))
                    if len(stats['actions']) > 100:
                        del(stats['actions'][0])
                    return id
            elif rule['condition']['type'] == '^contains':
                if lastval_from_rstate(rstate,entry[0]) and (
                    rule['condition']['value'] not in entry[1][rule['attribute']]):
                    id = action_mgr.add(rule['actions'])
                    rstate.lastval[entry[0]] = False
                    stats['actions'].append("TRIGGER:"+json.dumps(rstate.rule))
                    if len(stats['actions']) > 100:
                        del(stats['actions'][0])
                    return id
        else:
            log("DEBUG: key not in entry")
    log("DEBUG: nothing triggered")
    return None


def lastval_from_rstate(rstate, key):
    if key not in rstate.lastval:
        return False
    else:
        return rstate.lastval


def close_fds(leave_open=[0, 1, 2]):
    fds = os.listdir(b'/proc/self/fd')
    for fdn in fds:
        fd = int(fdn)
        if fd not in leave_open:
            try:
                os.close(fd)
            except Exception:
                pass


def log(message):
    with open("/tmp/log", "a+") as f:
        f.write(datetime.now().strftime("%y%m%dT%H%M%S")+" "+message+"\n")


class ActionQueueManager:
    ST_BUSY = "busy"
    ST_COMPLETE = "complete"
    ST_ERROR = "error"

    def __init__(self, stats, logger):
        self._pending = []
        self._queue = []
        self._die = False
        self._tid = thread.start_new_thread(self.run, ())
        self._lock = thread.allocate_lock()
        self._logger = logger
        self._stats = stats
        self._results = {}

    @property
    def results(self):
        return self._results

    def die(self):
        self._die = True

    def add(self, actions):
        ''' add a block of actions '''
        with self._lock:
            id = str(uuid.uuid4())
            for action in actions:
                self._pending.append(ActionEntry(action))
                self._pending[-1].batchid = id
            self._pending.append({'marker': id})
            self._results[id] = self.ST_BUSY
        return id

    def run(self):
        try:
            self._logger("AQM: starting")
            while not self._die:
                # add pending
                self._logger("AQM: pending len = "+str(len(self._pending)))
                with self._lock:
                    while len(self._pending) > 0:
                        self._logger("AQM: adding pending")
                        self._queue.append(self._pending.pop(0))

                # consume _queue
                self._logger("AQM: queue len = "+str(len(self._queue)))
                abort = False
                while len(self._queue) > 0:
                    action = self._queue[0]

                    if isinstance(action, dict) and 'marker' in action:
                        # finished this block of actions
                        self._results[action['marker']] = self.ST_COMPLETE
                        del self._queue[0]
                        continue

                    self._logger("AQM: processing action queue")

                    # sanity check for deployment id
                    # abort rule if doesn't exist
                    if not self._deployment_exists(client, action):
                        self._add_error("deployment {} doesn't exist".format(action['deployment_id']))
                        self._logger("ERROR: AQM: configured deployment {} doesn't exist".format(
                            action['deployment_id']))
                        self._logger("       ABORTING RULE")
                        abort = True
                        break

                    if action.status == action.STATUS_PENDING:
                        self._logger("Starting workflow {} on deployment {}".format(
                            action._action['workflow_id'],
                            action._action['deployment_id']))
                        # start workflow
                        wfargs = (action._action['workflow_args'] if
                                  'workflow_args' in action._action else {})
                        action.tries += 1
                        try:
                            execution = client.executions.start(
                                action._action['deployment_id'],
                                action._action['workflow_id'], wfargs)
                        except Exception as e:
                            self._add_error("exception: " +e.message)
                            self._logger("ERROR: caught exception: "+e.message)
                            if action.tries > action.retry_max:
                                self._logger("retries exhausted, aborting")
                                abort = True
                                break
                            continue

                        self._add_action("started execution "+execution.id)
                        action.set_attr(action.ATTR_EXID, execution.id)
                        action.status = action.STATUS_STARTED

                    elif action.status == action.STATUS_STARTED:
                        self._logger("DEBUG: action started, checking status")
                        # running execution, check if complete
                        try:
                            execution = client.executions.get(
                                action.get_attr(action.ATTR_EXID))
                        except Exception as e:
                            self._logger("exception caught getting execution:" +
                                e.message)
                            abort = True
                            break
                        status = execution.status
                        if status == action.EXEC_FAILED:
                            self._logger("execution returned failed status")
                            action.status = action.STATUS_ERROR
                            abort = True
                            break
                        elif status == action.EXEC_CANCELLED:
                            self._logger("execution returned cancelled status")
                            action.status = action.STATUS_CANCELLED
                            abort = True
                            break
                        elif status == action.EXEC_DONE:
                            self._logger("execution complete")
                            del self._queue[0]
                        else:
                            self._logger("INFO: got status=" + str(status))
                            time.sleep(4)

                # TODO : 2 seconds is arbitrary
                if abort:
                    #self._logger("INFO: processing abort of " + self._queue[0]['__id'])
                    self._logger("INFO: processing abort")
                    # consume any remaining tasks
                    while len(self._queue) > 0:
                        action = self._queue[0]
                        del self._queue[0]
                        if isinstance(action, dict) and 'marker' in action:
                            self._results[action['marker']] = self.ST_ERROR
                            break

                time.sleep(2)
        except Exception as e:
            self._logger("ERROR: AQM exception: "+e.message)

    def _add_action(self, action):
        self._stats['actions'] = action
        while len(self._stats['actions']) > 100:
            del self._stats['actions'][0]

    def _add_error(self, error):
        self._stats['errcnt'] += 1
        self._stats['last_error'] = error

    def _deployment_exists(self, client, action):
        did = action._action['deployment_id']
        dep = client.deployments.get(did)
        if dep:
            return True
        return False


class ActionEntry:
    STATUS_PENDING = 0
    STATUS_STARTED = 1
    STATUS_COMPLETE = 2
    STATUS_ERROR = 3
    STATUS_CANCELLED = 4
    ATTR_STATUS = "status"
    ATTR_EXID = "execution_id"
    ATTR_RETRY = "retry_cnt"
    RETRY_DEFAULT = 0
    EXEC_FAILED = "failed"
    EXEC_DONE = "terminated"
    EXEC_CANCELLED = "cancelled"

    def __init__(self, action):
        self._action = action
        self._state = {self.ATTR_STATUS: self.STATUS_PENDING}
        self._retry_max = (action['retries']
                           if 'retries' in action else self.RETRY_DEFAULT)
        self._tries = 0
        self._batchid = ""
        self._status = {}

    @property
    def status(self):
        return self._state[self.ATTR_STATUS]

    @property
    def retry_max(self):
        return self._retry_max

    @property
    def tries(self):
        return self._tries

    @status.setter
    def set_status(self, status):
        self._state[self.ATTR_STATUS] = status

    def set_attr(self, key, value):
        self._status[key] = value

    def get_attr(self, key):
        return self._status[key]

    @property
    def batchid(self):
        return self._batchid


class RuleProcessStatus:
    ST_INITIAL = "initial"
    ST_STARTED = "started"
    ST_COMPLETE = "complete"
    ST_ERROR = "error"

    def __init__(self, rule):
        self._rule = copy.deepcopy(rule)
        self._state = self.ST_INITIAL
        self._lastval = {}
        self._id = None

    @property
    def rule(self):
        return self._rule

    @property
    def state(self):
        return self._state

    @property
    def lastval(self):
        return self._lastval

    @property
    def id(self):
        self._id = id

############################
# REST API
############################

def set_routes(app, properties, stats, config):
    @app.route('/')
    def hello_world():
        return 'valid paths = /rules, /stats, /config'

    @app.route('/rules')
    def get_rules():
        return (json.dumps(properties['rules']))

    @app.route('/stats')
    def get_stats():
        return (json.dumps(stats))

    @app.route('/config')
    def get_config():
        return (json.dumps(config))
