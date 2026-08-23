#!/usr/bin/env nu
# demo-analyzer.nu — end-to-end analyzer demo
#
# Spins up a throwaway Loki container, pushes a handful of sample Falco-style
# syscall alerts into it, then runs the `analyzer` binary against it so you
# can see the full fetch -> obfuscate -> (dry-run) prompt pipeline without
# needing a real cluster.
#
# Usage:
#   nu scripts/demo-analyzer.nu            # dry-run (no LLM call, shows obfuscated prompt)
#   nu scripts/demo-analyzer.nu --live      # actually call the configured LLM provider
#   nu scripts/demo-analyzer.nu --keep      # leave the Loki container running afterward

def "main" [--live, --keep] {
    let loki_port = 3100
    let loki_url = $"http://localhost:($loki_port)"
    let container_name = "obfsck-demo-loki"

    if (which docker | length) == 0 {
        print "[fail] docker not on PATH — required to run a throwaway Loki instance"
        exit 1
    }

    print "=== obfsck analyzer demo ==="
    print $"[1/5] starting Loki \(($container_name)\) on port ($loki_port)"

    do { docker rm -f $container_name } | complete | ignore

    let run = (
        do {
            docker run -d --rm --name $container_name -p $"($loki_port):3100" grafana/loki:latest
        } | complete
    )
    if $run.exit_code != 0 {
        print $"[fail] could not start Loki container\n($run.stderr)"
        exit 1
    }

    print "[2/5] waiting for Loki to become ready"
    mut ready = false
    for _ in 1..30 {
        let ok = (try { http get $"($loki_url)/ready" | ignore; true } catch { false })
        if $ok {
            $ready = true
            break
        }
        sleep 1sec
    }
    if not $ready {
        print "[fail] Loki did not become ready in time"
        docker logs $container_name | print
        docker rm -f $container_name | ignore
        exit 1
    }
    print "[ok]   Loki is ready"

    print "[3/5] pushing sample syscall alerts"
    let now_ns = (date now | format date "%s%9f")
    let alerts = [
        {
            rule: "Terminal shell in container"
            priority: "warning"
            hostname: "web-7f9c8d-x2k4p"
            output: "A shell was spawned in a container with an attached terminal (user=root user_loginuid=1000 container_id=a1b2c3d4e5f6 container_name=payments-api shell=bash parent=containerd-shim cmdline=bash -i)"
            output_fields: {
                "container.image.repository": "registry.internal/payments-api"
                "syscall.type": "execve"
                "proc.name": "bash"
                "proc.pname": "containerd-shim"
            }
        }
        {
            rule: "Unexpected outbound connection"
            priority: "critical"
            hostname: "worker-3b7e1a-q9r2s"
            output: "Outbound connection to suspicious IP (connection=10.2.3.4:52142->185.220.101.7:443 user=svc-deploy proc=curl container_id=f6e5d4c3b2a1 container_name=deploy-runner)"
            output_fields: {
                "container.image.repository": "registry.internal/deploy-runner"
                "syscall.type": "connect"
                "proc.name": "curl"
                "proc.pname": "sh"
            }
        }
        {
            rule: "Sensitive file opened for reading"
            priority: "error"
            hostname: "db-1a2b3c-m4n5o"
            output: "Sensitive file opened for reading (file=/etc/shadow user=postgres container_id=9f8e7d6c5b4a container_name=analytics-db proc=cat)"
            output_fields: {
                "container.image.repository": "registry.internal/analytics-db"
                "syscall.type": "openat"
                "proc.name": "cat"
                "proc.pname": "bash"
            }
        }
    ]

    for alert in $alerts {
        let log_line = ({ output: $alert.output, output_fields: $alert.output_fields } | to json --raw)
        let payload = {
            streams: [
                {
                    stream: {
                        source: "syscall"
                        rule: $alert.rule
                        priority: $alert.priority
                        hostname: $alert.hostname
                    }
                    values: [[$now_ns, $log_line]]
                }
            ]
        }
        try {
            http post -t application/json $"($loki_url)/loki/api/v1/push" ($payload | to json) | ignore
        } catch { |err|
            print $"[fail] failed to push alert ($alert.rule)\n($err.msg)"
        }
    }
    print $"[ok]   pushed ($alerts | length) sample alerts"

    print "[4/5] running analyzer"
    mut args = [--backend loki --loki-url $loki_url --last 5m --limit 5 --verbose]
    if not $live {
        $args = ($args | append "--dry-run")
    }
    print $"      cargo run --bin analyzer -- ($args | str join ' ')"
    print ""
    cargo run --bin analyzer -- ...$args

    print ""
    print "[5/5] done"
    if $keep {
        print $"      Loki container ($container_name) left running on ($loki_url) — clean up with: docker rm -f ($container_name)"
    } else {
        docker rm -f $container_name | ignore
        print $"      Loki container ($container_name) removed"
    }
}
