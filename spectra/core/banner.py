# -*- coding: utf-8 -*-
"""
Banner display for Spectra
"""

from .console import console
from .config import config

def display_banner():
    """Exibe o banner da ferramenta e as informações iniciais."""
    banner = """
    
                                    d8P                     
                                  d888888P                   
 .d888b,?88,.d88b,  d8888b  d8888b  ?88'    88bd88b d888b8b  
 ?8b,   `?88'  ?88 d8b_,dP d8P' `P  88P     88P'  `d8P' ?88  
   `?8b   88b  d8P 88b     88b      88b    d88     88b  ,88b 
`?888P'   888888P' `?888P' `?888P'  `?8b  d88'     `?88P'`88b
          88P'                                             
         d88                                               
         ?8P                                               

                     by iuawsyukboasfuilj
"""
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(f"[bold]{config.app_name} - Web Security Suite v{config.version}[/bold]")
    console.print("[italic]Uma ferramenta de hacking ético para análise de segurança web.[/italic]")
    console.print("-" * 60)

def display_legal_warning():
    """Exibe o aviso legal."""
    warning = """
[bold yellow]⚠️  AVISO LEGAL ⚠️[/bold yellow]

Este script foi criado para fins estritamente educacionais.
O autor não se responsabiliza pelo mau uso desta ferramenta.
Use-o apenas em sistemas e redes para os quais você tenha
permissão explícita para testar. O acesso não autorizado
a sistemas de computador é ilegal e não recomendado.
    """
    console.print(warning)
    console.print("-" * 60)
