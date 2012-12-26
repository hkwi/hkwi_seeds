#!/bin/env python
# coding: UTF-8
import quantumclient
import argparse

ap = argparse.ArgumentParser(description="quantum network quick view")
ap.add_argument("--tenant")
ap.add_argument("--host")
ap.add_argument("--port", type=int)
ap_ns = ap.parse_args()

cli_opt = {"tenant":"default", "host":"127.0.0.1", "port":9696}
for k in cli_opt:
	if k in ap_ns and getattr(ap_ns,k) is not None:
		cli_opt[k] = getattr(ap_ns,k)

cli = quantumclient.Client(**cli_opt)
print "tenant: "+cli_opt["tenant"]
for net in cli.list_networks()["networks"]:
	print " network: "+net["id"]
	for port in cli.list_ports(net["id"])["ports"]:
		print "  port: "+port["id"]
		attachment = cli.show_port_attachment(net["id"], port["id"])["attachment"]
		if attachment:
			print "   attachment: "+attachment["id"]
		else:
			print "   attachment: None"

