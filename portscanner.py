#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Integrantes
- Eduardo dos Santos
- Jorge Gabriel
- Matheus Rosa
- Pedro Augusto
"""

import nmap
import xml.etree.ElementTree


def linha():
	print("------------------------------------\n")


def scan_padrao(argumento):
	try:
		ip_host = input("Forneça um IP:")
		if ip_host == '':
			ip_host = "0.0.0.0"
		print(f"Host: {ip_host}")
		linha()
		range_portas = input("Defina a range das portas:")
		if range_portas == '':
			range_portas = "1-443"
		print(f"range: {range_portas}")
		linha()
		print("Iniciando Scan:")
		linha()
		nm.scan(ip_host, range_portas, arguments=argumento)
		for host in nm.all_hosts():
			if nm[host].state() == "down":
				print("Host inválido/inativo")
				linha()
			else:
				with open('relatorio_scan.txt', 'w') as relatorio:
					relatorio.write("ScanPort")
					relatorio.write("------------------------------------\n")
					relatorio.write(f"Host: {host} | {nm[host].hostname()}\n")
					relatorio.write(f"Situação: {nm[host].state()}\n")
					relatorio.write("------------------------------------\n")
				print(f"Host: {host} | {nm[host].hostname()}")
				print(f"Situação: {nm[host].state()}")
				for proto in nm[host].all_protocols():
					linha()
					print(f"Protocolo : {proto}")	
					portas = nm[host][proto].keys()
					for porta in portas:
						state = nm[host][proto][porta]['state']
						nome_servico = nm[host][proto][porta]['name']
						with open('relatorio_scan.txt', 'a') as relatorio:
							relatorio.write(f"[+] Porta : {porta}\tSituação : {state}\tServiço : {nome_servico}\n")
						print(f"[+] Porta : {porta}\t\tSituação : {state}\t\tServiço : {nome_servico}")
		linha()
	except xml.etree.ElementTree.ParseError:
			print("Erro de permissão.")
			linha()
	except nmap.PortScannerError:
			print("Erro de permissão.")
			linha()

def scan_fingerprint(argumento):
	try:
		ip_host = input("Forneça um IP:")
		if ip_host == "":
			ip_host = "0.0.0.0"
		print(f"Host: {ip_host}")
		linha()
		# fiware fingerprint
		fiware_range_portas = "1026, 1883, 4041, 8666, 9001, 27017"
		fiware_ports = ["1026", "1883", "4041", "8666", "9001", "27017"]
		fiware_status = []
		# phpmyadmin fingerprint
		phpmyadmin_range_portas = "80, 443, 3306"
		phpmyadmin_ports = ["80", "443", "3306"]
		phpmyadmin_status = []
		# fiware scan
		nm.scan(ip_host, fiware_range_portas, arguments=argumento)
		for host in nm.all_hosts():
			if nm[host].state() == "down":
				print("Host inválido/inativo")
				linha()
			else:
				with open("relatorio_fingerprint.txt", "w") as relatorio:
					relatorio.write("------------------------------------\n")
					relatorio.write("Scan Fingerprints\n")
					relatorio.write("------------------------------------\n")
				print("Scan Fingerprints")
				for proto in nm[host].all_protocols():
					linha()
					print(f"Protocolo : {proto}")
					portas = nm[host][proto].keys()
					for porta in portas:
						state = nm[host][proto][porta]['state']
						nome_servico = nm[host][proto][porta]['name']
						with open("relatorio_fingerprint.txt", "a") as relatorio:
							relatorio.write(f"[+] Porta : {porta}\tSituação : {state}\tServiço : {nome_servico}\n")
						print(f"[+] Porta : {porta}\t\tSituação: {state}\t\tServiço : {nome_servico}")
						if not porta in fiware_ports and state == "open":
							fiware_status.append(1)
						else:
							fiware_status.append(0)
				if not 0 in fiware_status:
					linha()
					print("[!] 'Fiware' Detectado")
					with open("relatorio_fingerprint.txt", "a") as relatorio:
						relatorio.write("------------------------------------\n")
						relatorio.write("[!] 'Fiware' Detectado\n")
						relatorio.write("------------------------------------\n")
				else:
					linha()
					print("[!] 'Fiware' não detectado")
					with open("relatorio_fingerprint.txt", "a") as relatorio:
							relatorio.write("------------------------------------\n")
							relatorio.write("[!] 'Fiware' não detectado\n")
							relatorio.write("------------------------------------\n")
		linha()
		# phpmyadmin scan
		nm.scan(ip_host, phpmyadmin_range_portas, arguments=argumento)
		for host in nm.all_hosts():
			if nm[host].state() == "down":
				print("Host inválido/inativo")
				linha()
			else:
				for proto in nm[host].all_protocols():
					print(f"Protocolo : {proto}")
					portas = nm[host][proto].keys()
					for porta in portas:
						with open("relatorio_fingerprint.txt", "a") as relatorio:
							relatorio.write(f"[+] Porta : {porta}\tSituação : {state}\tServiço : {nome_servico}\n")
						state = nm[host][proto][porta]['state']
						nome_servico = nm[host][proto][porta]['name']
						print(f"[+] Porta : {porta}\t\tSituação : {state}\t\tServiço : {nome_servico}")
						if not porta in phpmyadmin_ports and state == "open":
							phpmyadmin_status.append(1)
						else:
							phpmyadmin_status.append(0)
				if not 0 in phpmyadmin_status:
					linha()
					print(f"[!] 'PhpMyAdmin' Detectado")
					with open("relatorio_fingerprint.txt", "a") as relatorio:
						relatorio.write("------------------------------------\n")
						relatorio.write("[!] 'PhpMyAdmin' Detectado\n")
						relatorio.write("------------------------------------\n")
				else:
					linha()
					print("[!] 'PhpMyAdmin' não detectado")
					with open("relatorio_fingerprint.txt", "a") as relatorio:
							relatorio.write("------------------------------------\n")
							relatorio.write('[!] "PhpMyAdmin" não detectado\n')
							relatorio.write("------------------------------------\n")
		linha()
	except xml.etree.ElementTree.ParseError:
			print("Erro de permissão")
			linha()
	except nmap.PortScannerError:
			print("Erro de permissão")
			linha()


nm = nmap.PortScanner()

while True:
	try:
		opt = int(input("Select a option:\n[1] Scan Padrão\n[2] Fingerprints\n[3] Exit\n: "))
		linha()
		if opt == 1:
			scan_padrao('-sS -sU')
		if opt == 2:
			scan_fingerprint("")
		if opt == 3: 
			exit()
		else:
			print("Selecione uma opção válida")
			linha()
	except ValueError:
		linha()
		print("Selecione uma opção válida")
		linha()