"""
Módulo para captura de banners de serviços de rede.
"""
import socket
from ..core.console import console


class BannerGrabber:
    """Classe para capturar banners de serviços de rede."""
    
    def __init__(self, timeout=4):
        """
        Inicializa o grabber de banners.
        
        Args:
            timeout (int): Timeout em segundos para conexões.
        """
        self.timeout = timeout
    
    def grab_banner(self, host, port):
        """
        Tenta se conectar a uma porta e capturar o banner do serviço.
        
        Args:
            host (str): Host alvo.
            port (int): Porta alvo.
            
        Returns:
            str: Banner capturado ou None se falhou.
        """
        console.print("-" * 60)
        console.print(f"[*] Capturando banner de [bold cyan]{host}:{port}[/bold cyan]")
        console.print("-" * 60)
        
        try:
            with console.status(f"[bold green]Conectando em {host}:{port}...[/bold green]"):
                with socket.socket() as s:
                    s.settimeout(self.timeout)
                    s.connect((host, port))
                    banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
            
            if banner:
                console.print(f"[bold green][+] Banner da porta {port}:[/bold green]")
                console.print(banner)
                return banner
            else:
                console.print(f"[bold yellow][-] Porta {port}: Banner vazio ou não recebido.[/bold yellow]")
                return None
                
        except Exception as e:
            console.print(f"[bold red][!] Erro ao conectar na porta {port}: {e}[/bold red]")
            return None
        finally:
            console.print("-" * 60)
    
    def grab_multiple_banners(self, host, ports):
        """
        Captura banners de múltiplas portas.
        
        Args:
            host (str): Host alvo.
            ports (list): Lista de portas.
            
        Returns:
            dict: Dicionário com porta:banner.
        """
        banners = {}
        for port in ports:
            banner = self.grab_banner(host, port)
            if banner:
                banners[port] = banner
        return banners
