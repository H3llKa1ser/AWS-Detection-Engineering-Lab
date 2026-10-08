# ---------------------------------------------------------------------------
# Network + DNS detection catalogue
#
# Same contract as catalogue.tf, plus:
#   source     - which telemetry the filter needs (vpc_flow | dns | dns_firewall;
#                dns_firewall reads the DNS query log group but only deploys
#                when DNS Firewall is enabled)
#   threshold  - matches per period before alarming (default 1)
#   flow_match - VPC Flow Log detections only: map of field => condition.
#                The space-delimited pattern is generated from flow_fields,
#                so you never hand-write 22 positional fields.
# ---------------------------------------------------------------------------

locals {
  # Must match the log_format order in modules/vpc-flow-logs/main.tf.
  flow_fields = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status",
    "vpc_id", "subnet_id", "instance_id", "tcp_flags", "type",
    "pkt_srcaddr", "pkt_dstaddr", "flow_direction",
  ]

  network_detections = {
    # --- VPC Flow Logs ------------------------------------------------------
    flow_ssh_rejected_ingress = {
      source      = "vpc_flow"
      description = "Burst of rejected inbound SSH (scan / brute force against port 22)"
      attack      = "T1110 Brute Force / T1046 Network Service Discovery"
      threshold   = 20
      flow_match  = { action = "=\"REJECT\"", dstport = "=\"22\"", flow_direction = "=\"ingress\"" }
    }
    flow_rdp_rejected_ingress = {
      source      = "vpc_flow"
      description = "Burst of rejected inbound RDP (scan / brute force against port 3389)"
      attack      = "T1110 Brute Force / T1046 Network Service Discovery"
      threshold   = 20
      flow_match  = { action = "=\"REJECT\"", dstport = "=\"3389\"", flow_direction = "=\"ingress\"" }
    }
    flow_reject_spike = {
      source      = "vpc_flow"
      description = "High volume of rejected flows across the VPC (port scan or misconfigured workload)"
      attack      = "T1046 Network Service Discovery"
      threshold   = 500
      flow_match  = { action = "=\"REJECT\"" }
    }
    flow_egress_smb_accepted = {
      source      = "vpc_flow"
      description = "Accepted outbound SMB (445): lateral movement or exfil over SMB"
      attack      = "T1021.002 SMB/Windows Admin Shares / T1048 Exfiltration Over Alternative Protocol"
      threshold   = 1
      flow_match  = { action = "=\"ACCEPT\"", dstport = "=\"445\"", flow_direction = "=\"egress\"" }
    }
    flow_large_egress_transfer = {
      source      = "vpc_flow"
      description = "Single 1-minute egress flow over 500 MB (bulk data leaving an interface)"
      attack      = "T1048 Exfiltration Over Alternative Protocol / T1567 Exfiltration Over Web Service"
      threshold   = 1
      flow_match  = { action = "=\"ACCEPT\"", bytes = ">500000000", flow_direction = "=\"egress\"" }
    }

    # --- Route 53 Resolver query logs (JSON) -----------------------------------
    dns_nxdomain_spike = {
      source      = "dns"
      description = "Spike in NXDOMAIN responses (DGA beaconing or a misbehaving client)"
      attack      = "T1568.002 Dynamic Resolution: Domain Generation Algorithms"
      threshold   = 50
      pattern     = "{ $.rcode = \"NXDOMAIN\" }"
    }
    dns_txt_query_spike = {
      source      = "dns"
      description = "High volume of TXT queries (DNS tunnelling / C2 over DNS)"
      attack      = "T1071.004 Application Layer Protocol: DNS"
      threshold   = 100
      pattern     = "{ $.query_type = \"TXT\" }"
    }
    dns_mining_pool_lookup = {
      source      = "dns"
      description = "Lookup of a known cryptomining pool domain"
      attack      = "T1496 Resource Hijacking"
      threshold   = 1
      pattern     = "{ ($.query_name = \"*.nanopool.org.\") || ($.query_name = \"*.supportxmr.com.\") || ($.query_name = \"*.minexmr.com.\") || ($.query_name = \"*.moneroocean.stream.\") || ($.query_name = \"*.hashvault.pro.\") }"
    }
    dns_onion_lookup = {
      source      = "dns"
      description = "Lookup of a .onion name (Tor client or Tor-routed malware)"
      attack      = "T1090.003 Proxy: Multi-hop Proxy"
      threshold   = 1
      pattern     = "{ $.query_name = \"*.onion.\" }"
    }

    # --- DNS Firewall verdicts (written into the Resolver query logs) -----------
    dns_firewall_block = {
      source      = "dns_firewall"
      description = "DNS Firewall blocked a query (threat-listed or denylisted domain). The block stopped resolution, not the compromise: find the asking host"
      attack      = "T1071.004 Application Layer Protocol: DNS / T1568 Dynamic Resolution"
      threshold   = 1
      pattern     = "{ $.firewall_rule_action = \"BLOCK\" }"
    }
    dns_firewall_alert = {
      source      = "dns_firewall"
      description = "DNS Firewall ALERT rule matched (list in evaluation mode, query was answered)"
      attack      = "T1071.004 Application Layer Protocol: DNS / T1568 Dynamic Resolution"
      threshold   = 1
      pattern     = "{ $.firewall_rule_action = \"ALERT\" }"
    }
  }
}
