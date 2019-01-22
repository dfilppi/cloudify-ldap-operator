# Cloudify Operator

Base project for writing Cloudify operators.  Since an operator is a background process (in the generic sense), it needs to provide visibility.  Since Cloudify provides visibility via executions, another method needs to be used.  For this framework, a simple REST API is provided for gathering status.  Ideally a widget for the Cloudify dashboard should be provided to supply visibility of operators.


# Dev notes (delete)

- decided on simple function definition implementation inside example.  The production wy to do it would implement the operator code itself inside a plugin and call it from this project.
