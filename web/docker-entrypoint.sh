#!/bin/sh
set -eu

# The non-internal bridge exists solely so Docker Desktop can publish the
# host port. Remove every default route before nginx starts: connected routes
# to both Docker subnets remain, so host ingress and web-api proxying work,
# while arbitrary outbound traffic has no route.
while ip route del default 2>/dev/null; do
    :
done

exec nginx -g "daemon off;"
