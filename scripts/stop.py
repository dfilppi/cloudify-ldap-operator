from cloudify import ctx
import os

# Stops the operator

pid = ctx.instance.runtime_properties['pid']

ctx.logger.info("stopping process {}".format(pid))

res = os.system("kill "+str(pid))

if res != 0: 
    ctx.logger.error("kill failed for pid ".format(pid))
