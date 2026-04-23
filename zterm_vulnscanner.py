#!/usr/bin/env python3
"""
ZTermPro VulnScanner Auto
Um wrapper automatizado que executa nmap silencioso e cruza informações com APIs públicas de CVE.
Gera um relatório em Markdown no final.

Requisitos:
- nmap instalado no sistema
- pip install python-nmap requests
"""

import nmap
import requests
import argparse
import sys
import json
from datetime import datetime
import os

def print_banner():
    banner = """
    ================================================
    [+] ZTermPro - Vulnerability Scanner Wrapper [+]
    ================================================
    """
    print(banner)

def run_nmap_scan(target):
    print(f"[*] Iniciando scan silencioso em {target}...")
    nm = nmap.PortScanner()
    
    try:
        # -sT: TCP connect scan (doesn't require root like -sS)
        # -T4: Aggressive timing
        # -Pn: Treat all hosts as online
        # -sV: Probe open ports to determine service/version info
        nm.scan(hosts=target, arguments='-sT -T4 -Pn -sV')
    except nmap.PortScannerError as e:
        print(f"[-] Erro ao executar nmap: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Erro inesperado: {e}")
        sys.exit(1)
        
    return nm

def check_cve_for_service(service, version):
    """
    Consulta uma API pública de CVE para encontrar possíveis vulnerabilidades.
    Este é um exemplo utilizando a API pública cve.circl.lu.
    Em um cenário real de produção, é recomendável usar NVD API com uma API Key.
    """
    if not version or not service:
        return []
        
    api_url = f"https://cve.circl.lu/api/search/{service}/{version}"
    
    try:
        # O timeout evita que o script trave caso a API esteja fora do ar
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            cves = []
            if data and isinstance(data, list):
                # Retorna os top 3 CVEs mais recentes/relevantes encontrados
                for item in data[:3]:
                    cves.append({
                        'id': item.get('id', 'Desconhecido'),
                        'summary': item.get('summary', 'Sem descrição.'),
                        'cvss': item.get('cvss', 'N/A')
                    })
            return cves
    except requests.exceptions.RequestException:
        pass
    
    return []

def generate_markdown_report(target, scan_results, cve_results, output_file):
    print(f"[*] Gerando relatório em {output_file}...")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Relatório de Vulnerabilidades - {target}\n\n")
        f.write(f"**Data do Scan:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        
        if not scan_results.all_hosts():
            f.write("Nenhum host encontrado ou escaneado.\n")
            return
            
        for host in scan_results.all_hosts():
            f.write(f"## Host: {host} ({scan_results[host].hostname()})\n")
            f.write(f"**Estado:** {scan_results[host].state()}\n\n")
            
            for proto in scan_results[host].all_protocols():
                f.write(f"### Protocolo: {proto.upper()}\n\n")
                
                ports = scan_results[host][proto].keys()
                for port in sorted(ports):
                    port_info = scan_results[host][proto][port]
                    state = port_info['state']
                    service = port_info['name']
                    product = port_info['product']
                    version = port_info['version']
                    
                    f.write(f"#### Porta {port} - {service} ({state})\n")
                    if product:
                        f.write(f"- **Produto:** {product} {version}\n")
                    else:
                        f.write(f"- **Produto:** Desconhecido\n")
                    
                    # Busca os CVEs no dicionário
                    service_cves = cve_results.get(f"{host}:{port}", [])
                    if service_cves:
                        f.write("- **Possíveis Vulnerabilidades (CVEs):**\n")
                        for cve in service_cves:
                            f.write(f"  - **{cve['id']}** (CVSS: {cve['cvss']}): {cve['summary']}\n")
                    else:
                        f.write("- *Nenhuma vulnerabilidade aparente ou versão desconhecida.*\n")
                    f.write("\n")
                    
        f.write("---\n")
        f.write("*Gerado automaticamente por ZTermPro VulnScanner*\n")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="ZTermPro VulnScanner - Automatiza nmap e verificação de CVEs")
    parser.add_argument("-t", "--target", required=True, help="IP Alvo ou Range (ex: 192.168.1.1 ou 10.0.0.0/24)")
    parser.add_argument("-o", "--output", default="scan_report.md", help="Arquivo de saída do relatório em Markdown")
    
    args = parser.parse_args()
    
    nm = run_nmap_scan(args.target)
    
    cve_results = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                
                if product and version:
                    print(f"[*] Consultando CVEs para {product} {version} (Porta {port})...")
                    # Em alguns casos, a formatação do nome do produto pode precisar de tratamento (ex: lowercase)
                    cves = check_cve_for_service(product.lower(), version)
                    cve_results[f"{host}:{port}"] = cves
    
    generate_markdown_report(args.target, nm, cve_results, args.output)
    print(f"[+] Concluído! Relatório salvo em: {args.output}")

if __name__ == "__main__":
    main()
