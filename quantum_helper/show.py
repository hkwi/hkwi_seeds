import quantumclient

cli = quantumclient.Client(tenant="default")
for net in cli.list_networks()["networks"]:
	print "network: "+net["id"]
	for port in cli.list_ports(net["id"])["ports"]:
		print " port: "+port["id"]
		attachment = cli.show_port_attachment(net["id"], port["id"])["attachment"]
		if attachment:
			print "  attachment: "+attachment["id"]
		else:
			print "  attachment: None"
