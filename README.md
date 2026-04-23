# ZTerm VulnScanner (Automatizado)

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-2B3B52?style=for-the-badge&logo=linux&logoColor=white)
![Security](https://img.shields.io/badge/Security-Red_Team-red?style=for-the-badge)

O ZTerm VulnScanner é um wrapper automatizado em Python que integra reconhecimento de rede com bancos de dados de vulnerabilidades. Ele executa um scan silencioso com o Nmap em um IP ou intervalo de IPs (range), identifica portas e serviços abertos, e cruza essas informações automaticamente com uma API pública de CVE (Common Vulnerabilities and Exposures) para gerar um relatório de fácil leitura em formato Markdown.

## 🎯 Funcionalidades
- **Scan Silencioso com Nmap**: Utiliza a biblioteca `python-nmap` para detecção de serviços e versões (`-sV`, `-sT`).
- **Cruzamento de CVEs**: Conecta-se a APIs públicas de vulnerabilidades (ex: CIRCL CVE API) para buscar vulnerabilidades conhecidas associadas às versões de software detectadas.
- **Relatórios Automatizados**: Gera um relatório limpo e estruturado em Markdown, contendo as portas abertas, serviços detectados e uma lista de possíveis vulnerabilidades junto com suas pontuações CVSS.

## 🛠️ Pré-requisitos
- Python 3.x
- `nmap` instalado no sistema.
- Bibliotecas Python necessárias:
  ```bash
  pip install python-nmap requests
  ```

## 🚀 Como Usar
```bash
python3 zterm_vulnscanner.py -t <IP_OU_RANGE> [-o <ARQUIVO_DE_SAIDA.md>]
```

**Exemplo:**
```bash
python3 zterm_vulnscanner.py -t 192.168.1.1 -o relatorio_servidor_db.md
```

## 🛡️ Habilidades Demonstradas
- Programação Python focada em cibersegurança.
- Mapeamento e reconhecimento de redes.
- Integração com APIs e manipulação de JSON.
- Automação de relatórios de segurança.
