"""
Módulo para extração de metadados de imagens.
"""
import requests
from io import BytesIO
from PIL import Image
from PIL.ExifTags import TAGS
from rich.table import Table

from ..core.console import console
from ..core.logger import logger
from ..utils.network import create_session


class MetadataExtractor:
    """Classe para extrair metadados EXIF de imagens."""
    
    def __init__(self, timeout=10):
        """
        Inicializa o extrator de metadados.
        
        Args:
            timeout (int): Timeout em segundos para requisições.
        """
        self.timeout = timeout
        self.session = create_session(timeout=timeout)
        logger.info("Extrator de metadados inicializado")
    
    def extract_metadata(self, image_url):
        """
        Descarrega uma imagem de um URL e extrai os seus metadados EXIF.
        
        Args:
            image_url (str): URL da imagem para extrair metadados.
            
        Returns:
            dict: Dicionário com metadados EXIF extraídos ou None se falhou.
        """
        console.print("-" * 60)
        console.print(f"[*] A extrair metadados de: [bold cyan]{image_url}[/bold cyan]")
        console.print("-" * 60)
        
        try:
            with console.status("[bold green]A descarregar e analisar a imagem...[/bold green]"):
                response = self.session.get(image_url, timeout=self.timeout, verify=False)
                response.raise_for_status()
                img = Image.open(BytesIO(response.content))
                # getexif() é a API pública desde Pillow 6+ e única desde Pillow 10+
                # _getexif() foi removida em Pillow 10
                exif_data = img.getexif() if hasattr(img, 'getexif') else img._getexif()  # type: ignore[attr-defined]

            if not exif_data:
                console.print("[bold yellow][-] Não foram encontrados metadados EXIF nesta imagem.[/bold yellow]")
                logger.info(f"Nenhum metadado EXIF encontrado para {image_url}")
                return None
            
            # Converte dados EXIF para formato legível
            metadata = {}
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='ignore')
                    except:
                        value = str(value)
                else:
                    value = str(value)
                metadata[tag_name] = value
            
            # Exibe resultados em tabela
            self._display_metadata(metadata)
            
            logger.info(f"Metadados extraídos com sucesso de {image_url}")
            return metadata

        except requests.exceptions.RequestException as e:
            console.print(f"[bold red][!] Erro ao descarregar a imagem: {e}[/bold red]")
            logger.error(f"Erro ao descarregar imagem {image_url}: {e}")
            return None
        except IOError:
            console.print("[bold red][!] Erro: O ficheiro não é uma imagem válida ou está corrompido.[/bold red]")
            logger.error(f"Arquivo inválido ou corrompido: {image_url}")
            return None
        except Exception as e:
            console.print(f"[bold red][!] Ocorreu um erro inesperado: {e}[/bold red]")
            logger.error(f"Erro inesperado ao extrair metadados de {image_url}: {e}")
            return None
        finally:
            console.print("-" * 60)
    
    def _display_metadata(self, metadata):
        """
        Exibe metadados em formato de tabela.
        
        Args:
            metadata (dict): Dicionário com metadados EXIF.
        """
        table = Table(title="Metadados EXIF Encontrados")
        table.add_column("Tag", justify="right", style="cyan", no_wrap=True)
        table.add_column("Valor", style="magenta")
        
        for tag_name, value in metadata.items():
            table.add_row(str(tag_name), str(value))
        
        console.print(table)
    
    def extract_multiple_metadata(self, image_urls):
        """
        Extrai metadados de múltiplas imagens.
        
        Args:
            image_urls (list): Lista de URLs de imagens.
            
        Returns:
            dict: Dicionário com URL:metadata para cada imagem.
        """
        results = {}
        
        for url in image_urls:
            metadata = self.extract_metadata(url)
            if metadata:
                results[url] = metadata
        
        return results
    
    def get_sensitive_metadata(self, metadata):
        """
        Identifica metadados potencialmente sensíveis.
        
        Args:
            metadata (dict): Dicionário com metadados EXIF.
            
        Returns:
            dict: Dicionário com metadados sensíveis identificados.
        """
        if not metadata:
            return {}
        
        sensitive_tags = [
            'GPS', 'GPSInfo', 'GPSLatitude', 'GPSLongitude', 'GPSAltitude',
            'DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
            'Make', 'Model', 'Software', 'Artist', 'Copyright',
            'XPAuthor', 'XPComment', 'XPKeywords', 'XPSubject', 'XPTitle',
            'UserComment', 'ImageDescription'
        ]
        
        sensitive_data = {}
        
        for tag_name, value in metadata.items():
            if any(sensitive_tag.lower() in tag_name.lower() for sensitive_tag in sensitive_tags):
                sensitive_data[tag_name] = value
        
        return sensitive_data
    
    def analyze_metadata_privacy(self, metadata):
        """
        Analisa metadados para identificar riscos de privacidade.
        
        Args:
            metadata (dict): Dicionário com metadados EXIF.
            
        Returns:
            dict: Relatório de análise de privacidade.
        """
        if not metadata:
            return {"risk_level": "none", "issues": []}
        
        sensitive_data = self.get_sensitive_metadata(metadata)
        issues = []
        risk_level = "low"
        
        # Verifica informações de GPS
        gps_tags = ['GPS', 'GPSInfo', 'GPSLatitude', 'GPSLongitude']
        if any(tag in metadata for tag in gps_tags):
            issues.append("Informações de localização GPS detectadas")
            risk_level = "high"
        
        # Verifica informações de dispositivo
        device_tags = ['Make', 'Model', 'Software']
        device_info = [tag for tag in device_tags if tag in metadata]
        if device_info:
            issues.append(f"Informações do dispositivo detectadas: {', '.join(device_info)}")
            if risk_level == "low":
                risk_level = "medium"
        
        # Verifica informações pessoais
        personal_tags = ['Artist', 'Copyright', 'XPAuthor', 'UserComment']
        personal_info = [tag for tag in personal_tags if tag in metadata]
        if personal_info:
            issues.append(f"Informações pessoais detectadas: {', '.join(personal_info)}")
            if risk_level == "low":
                risk_level = "medium"
        
        # Verifica timestamps
        time_tags = ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']
        time_info = [tag for tag in time_tags if tag in metadata]
        if time_info:
            issues.append(f"Timestamps detectados: {', '.join(time_info)}")
            if risk_level == "low":
                risk_level = "medium"
        
        return {
            "risk_level": risk_level,
            "issues": issues,
            "sensitive_data": sensitive_data,
            "total_metadata_tags": len(metadata)
        }


# Função para compatibilidade com versão anterior
def extract_metadata(image_url):
    """
    Função legacy para compatibilidade - extrai metadados de uma imagem.
    
    Args:
        image_url (str): URL da imagem.
        
    Returns:
        dict: Metadados extraídos ou None.
    """
    extractor = MetadataExtractor()
    return extractor.extract_metadata(image_url)
