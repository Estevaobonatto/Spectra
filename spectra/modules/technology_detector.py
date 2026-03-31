# -*- coding: utf-8 -*-
"""
Módulo de Detecção de Tecnologias Web
Identifica tecnologias, frameworks e serviços utilizados em sites
"""

import re
import requests
import hashlib
import asyncio
import aiohttp
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from ..core.console import console
from ..core.logger import get_logger
from ..utils.network import create_session

logger = get_logger(__name__)

class AdvancedTechnologyDetector:
    """Detector avançado de tecnologias web."""
    
    def __init__(self, url, timeout=10, retries=3):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.timeout = timeout
        self.retries = retries
        self.session = create_session()
        
        # Resultados estruturados
        self.detections = {
            'web_servers': [],
            'frontend_frameworks': [],
            'backend_technologies': [],
            'cms_platforms': [],
            'javascript_libraries': [],
            'css_frameworks': [],
            'cdn_services': [],
            'security_technologies': [],
            'analytics_tools': [],
            'development_tools': [],
            'databases': [],
            'cloud_services': []
        }
        
        logger.info(f"Detector de tecnologias inicializado para {self.url}")
        
        # Database expandida de tecnologias
        self._init_expanded_technology_database()
        
        # Sistema de fingerprinting
        self.file_hashes = {}
        self._init_file_fingerprints()
        
        # Cache de resultados
        self.cache = {}
        
        # Threading
        self.max_workers = 10
    
    def _init_expanded_technology_database(self):
        """Inicializa database expandida de tecnologias baseada em Wappalyzer."""
        self.tech_database = {
            'headers': {
                'Server': {
                    # Web Servers
                    'nginx': {'name': 'Nginx', 'category': 'web_servers', 'version_regex': r'nginx/([\d\.]+)'},
                    'apache': {'name': 'Apache HTTP Server', 'category': 'web_servers', 'version_regex': r'Apache/([\d\.]+)'},
                    'microsoft-iis': {'name': 'Microsoft IIS', 'category': 'web_servers', 'version_regex': r'Microsoft-IIS/([\\d\\.]+)'},
                    'litespeed': {'name': 'LiteSpeed', 'category': 'web_servers', 'version_regex': r'LiteSpeed/([\\d\\.]+)'},
                    'caddy': {'name': 'Caddy', 'category': 'web_servers', 'version_regex': r'Caddy/([\\d\\.]+)'},
                    'gunicorn': {'name': 'Gunicorn', 'category': 'web_servers', 'version_regex': r'gunicorn/([\\d\\.]+)'},
                    'openresty': {'name': 'OpenResty', 'category': 'web_servers', 'version_regex': r'openresty/([\\d\\.]+)'},
                    'tomcat': {'name': 'Apache Tomcat', 'category': 'web_servers', 'version_regex': r'Apache-Coyote/([\\d\\.]+)'},
                    'jetty': {'name': 'Jetty', 'category': 'web_servers', 'version_regex': r'Jetty/([\\d\\.]+)'},
                    'uvicorn': {'name': 'Uvicorn', 'category': 'web_servers', 'version_regex': r'uvicorn/([\\d\\.]+)'},
                    'waitress': {'name': 'Waitress', 'category': 'web_servers', 'version_regex': r'waitress/([\\d\\.]+)'},
                    'cherokee': {'name': 'Cherokee', 'category': 'web_servers', 'version_regex': r'Cherokee/([\\d\\.]+)'},
                    'lighttpd': {'name': 'Lighttpd', 'category': 'web_servers', 'version_regex': r'lighttpd/([\\d\\.]+)'},
                    'h2o': {'name': 'H2O', 'category': 'web_servers', 'version_regex': r'h2o/([\\d\\.]+)'},
                    'tengine': {'name': 'Tengine', 'category': 'web_servers', 'version_regex': r'Tengine/([\\d\\.]+)'},
                    'traefik': {'name': 'Traefik', 'category': 'web_servers', 'version_regex': r'Traefik/([\\d\\.]+)'},
                    
                    # CDN/Cloud Services
                    'cloudflare': {'name': 'Cloudflare', 'category': 'cdn_services', 'version_regex': None},
                    'aws': {'name': 'Amazon AWS', 'category': 'cloud_services', 'version_regex': None},
                    'amazon': {'name': 'Amazon AWS', 'category': 'cloud_services', 'version_regex': None},
                    'google': {'name': 'Google Cloud', 'category': 'cloud_services', 'version_regex': None},
                    'microsoft-azure': {'name': 'Microsoft Azure', 'category': 'cloud_services', 'version_regex': None},
                    
                    # Application Servers
                    'websphere': {'name': 'IBM WebSphere', 'category': 'web_servers', 'version_regex': r'WebSphere/([\\d\\.]+)'},
                    'weblogic': {'name': 'Oracle WebLogic', 'category': 'web_servers', 'version_regex': r'WebLogic/([\\d\\.]+)'},
                    'jboss': {'name': 'JBoss', 'category': 'web_servers', 'version_regex': r'JBoss/([\\d\\.]+)'},
                    'wildfly': {'name': 'WildFly', 'category': 'web_servers', 'version_regex': r'WildFly/([\\d\\.]+)'},
                },
                'X-Powered-By': {
                    # Backend Technologies
                    'php': {'name': 'PHP', 'category': 'backend_technologies', 'version_regex': r'PHP/([\\d\\.]+)'},
                    'asp.net': {'name': 'ASP.NET', 'category': 'backend_technologies', 'version_regex': r'ASP\\.NET.*?([\\d\\.]+)'},
                    'express': {'name': 'Express.js', 'category': 'backend_technologies', 'version_regex': r'Express/([\\d\\.]+)'},
                    'django': {'name': 'Django', 'category': 'backend_technologies', 'version_regex': r'Django/([\\d\\.]+)'},
                    'rails': {'name': 'Ruby on Rails', 'category': 'backend_technologies', 'version_regex': r'Rails ([\\d\\.]+)'},
                    'laravel': {'name': 'Laravel', 'category': 'backend_technologies', 'version_regex': r'Laravel/([\\d\\.]+)'},
                    'next.js': {'name': 'Next.js', 'category': 'frontend_frameworks', 'version_regex': r'Next\\.js/([\\d\\.]+)'},
                    'node.js': {'name': 'Node.js', 'category': 'backend_technologies', 'version_regex': r'Node\\.js/([\\d\\.]+)'},
                    'flask': {'name': 'Flask', 'category': 'backend_technologies', 'version_regex': r'Flask/([\\d\\.]+)'},
                    'fastapi': {'name': 'FastAPI', 'category': 'backend_technologies', 'version_regex': r'FastAPI/([\\d\\.]+)'},
                    'spring': {'name': 'Spring Framework', 'category': 'backend_technologies', 'version_regex': r'Spring/([\\d\\.]+)'},
                    'struts': {'name': 'Apache Struts', 'category': 'backend_technologies', 'version_regex': r'Struts/([\\d\\.]+)'},
                    'zend': {'name': 'Zend Framework', 'category': 'backend_technologies', 'version_regex': r'Zend/([\\d\\.]+)'},
                    'codeigniter': {'name': 'CodeIgniter', 'category': 'backend_technologies', 'version_regex': r'CodeIgniter/([\\d\\.]+)'},
                    'symfony': {'name': 'Symfony', 'category': 'backend_technologies', 'version_regex': r'Symfony/([\\d\\.]+)'},
                    'cakephp': {'name': 'CakePHP', 'category': 'backend_technologies', 'version_regex': r'CakePHP/([\\d\\.]+)'},
                    'yii': {'name': 'Yii Framework', 'category': 'backend_technologies', 'version_regex': r'Yii/([\\d\\.]+)'},
                    'phalcon': {'name': 'Phalcon', 'category': 'backend_technologies', 'version_regex': r'Phalcon/([\\d\\.]+)'},
                    'gin': {'name': 'Gin (Go)', 'category': 'backend_technologies', 'version_regex': r'Gin/([\\d\\.]+)'},
                    'echo': {'name': 'Echo (Go)', 'category': 'backend_technologies', 'version_regex': r'Echo/([\\d\\.]+)'},
                    'sinatra': {'name': 'Sinatra', 'category': 'backend_technologies', 'version_regex': r'Sinatra/([\\d\\.]+)'},
                    'tornado': {'name': 'Tornado', 'category': 'backend_technologies', 'version_regex': r'Tornado/([\\d\\.]+)'},
                    'cherrypy': {'name': 'CherryPy', 'category': 'backend_technologies', 'version_regex': r'CherryPy/([\\d\\.]+)'},
                    'bottle': {'name': 'Bottle', 'category': 'backend_technologies', 'version_regex': r'Bottle/([\\d\\.]+)'},
                    'pyramid': {'name': 'Pyramid', 'category': 'backend_technologies', 'version_regex': r'Pyramid/([\\d\\.]+)'},
                    'starlette': {'name': 'Starlette', 'category': 'backend_technologies', 'version_regex': r'Starlette/([\\d\\.]+)'},
                    'quart': {'name': 'Quart', 'category': 'backend_technologies', 'version_regex': r'Quart/([\\d\\.]+)'},
                },
                'X-Generator': {
                    'wordpress': {'name': 'WordPress', 'category': 'cms_platforms', 'version_regex': r'WordPress ([\\d\\.]+)'},
                    'drupal': {'name': 'Drupal', 'category': 'cms_platforms', 'version_regex': r'Drupal ([\\d\\.]+)'},
                    'joomla': {'name': 'Joomla', 'category': 'cms_platforms', 'version_regex': r'Joomla ([\\d\\.]+)'},
                    'magento': {'name': 'Magento', 'category': 'cms_platforms', 'version_regex': r'Magento ([\\d\\.]+)'},
                    'shopify': {'name': 'Shopify', 'category': 'cms_platforms', 'version_regex': r'Shopify ([\\d\\.]+)'},
                    'woocommerce': {'name': 'WooCommerce', 'category': 'cms_platforms', 'version_regex': r'WooCommerce ([\\d\\.]+)'},
                    'prestashop': {'name': 'PrestaShop', 'category': 'cms_platforms', 'version_regex': r'PrestaShop ([\\d\\.]+)'},
                    'opencart': {'name': 'OpenCart', 'category': 'cms_platforms', 'version_regex': r'OpenCart ([\\d\\.]+)'},
                    'typo3': {'name': 'TYPO3', 'category': 'cms_platforms', 'version_regex': r'TYPO3 ([\\d\\.]+)'},
                    'concrete5': {'name': 'Concrete5', 'category': 'cms_platforms', 'version_regex': r'Concrete5 ([\\d\\.]+)'},
                    'ghost': {'name': 'Ghost', 'category': 'cms_platforms', 'version_regex': r'Ghost ([\\d\\.]+)'},
                    'jekyll': {'name': 'Jekyll', 'category': 'cms_platforms', 'version_regex': r'Jekyll ([\\d\\.]+)'},
                    'hugo': {'name': 'Hugo', 'category': 'cms_platforms', 'version_regex': r'Hugo ([\\d\\.]+)'},
                    'gatsby': {'name': 'Gatsby', 'category': 'cms_platforms', 'version_regex': r'Gatsby ([\\d\\.]+)'},
                    'nuxt': {'name': 'Nuxt.js', 'category': 'frontend_frameworks', 'version_regex': r'Nuxt ([\\d\\.]+)'},
                    'hexo': {'name': 'Hexo', 'category': 'cms_platforms', 'version_regex': r'Hexo ([\\d\\.]+)'},
                },
                # WAF Detection Headers
                'CF-RAY': {'cloudflare': {'name': 'Cloudflare WAF', 'category': 'security_technologies', 'version_regex': None}},
                'X-Sucuri-ID': {'sucuri': {'name': 'Sucuri WAF', 'category': 'security_technologies', 'version_regex': None}},
                'X-Akamai-Transformed': {'akamai': {'name': 'Akamai WAF', 'category': 'security_technologies', 'version_regex': None}},
                'X-Incap-Session': {'incapsula': {'name': 'Incapsula WAF', 'category': 'security_technologies', 'version_regex': None}},
                'X-CDN': {'maxcdn': {'name': 'MaxCDN', 'category': 'cdn_services', 'version_regex': None}},
                'X-Fastly-Request-ID': {'fastly': {'name': 'Fastly CDN', 'category': 'cdn_services', 'version_regex': None}},
                'X-Served-By': {'fastly': {'name': 'Fastly CDN', 'category': 'cdn_services', 'version_regex': None}},
                'X-Cache': {'varnish': {'name': 'Varnish Cache', 'category': 'web_servers', 'version_regex': None}},
                'X-Varnish': {'varnish': {'name': 'Varnish Cache', 'category': 'web_servers', 'version_regex': None}},
                'X-Cacheable': {'varnish': {'name': 'Varnish Cache', 'category': 'web_servers', 'version_regex': None}},
                'X-Drupal-Cache': {'drupal': {'name': 'Drupal Cache', 'category': 'cms_platforms', 'version_regex': None}},
                'X-Pingback': {'wordpress': {'name': 'WordPress', 'category': 'cms_platforms', 'version_regex': None}},
                'X-Frame-Options': {'security': {'name': 'Security Headers', 'category': 'security_technologies', 'version_regex': None}},
                'Content-Security-Policy': {'csp': {'name': 'Content Security Policy', 'category': 'security_technologies', 'version_regex': None}},
                'Strict-Transport-Security': {'hsts': {'name': 'HSTS', 'category': 'security_technologies', 'version_regex': None}},
                'X-Content-Type-Options': {'security': {'name': 'Security Headers', 'category': 'security_technologies', 'version_regex': None}},
                'X-XSS-Protection': {'xss_protection': {'name': 'XSS Protection', 'category': 'security_technologies', 'version_regex': None}},
                'Referrer-Policy': {'referrer_policy': {'name': 'Referrer Policy', 'category': 'security_technologies', 'version_regex': None}},
            },
            'html_content': {
                # CMS Platforms
                'wordpress': {'name': 'WordPress', 'category': 'cms_platforms', 'patterns': [
                    r'wp-content', r'wp-includes', r'wp-admin', r'WordPress', r'wp_enqueue_script',
                    r'wp-json', r'wp_localize_script', r'wp-emoji-release.min.js', r'wp-embed.min.js'
                ]},
                'drupal': {'name': 'Drupal', 'category': 'cms_platforms', 'patterns': [
                    r'drupal', r'sites/default', r'sites/all', r'drupal.js', r'Drupal.settings',
                    r'drupal-core', r'misc/drupal.js', r'Drupal.behaviors'
                ]},
                'joomla': {'name': 'Joomla', 'category': 'cms_platforms', 'patterns': [
                    r'joomla', r'com_content', r'mod_', r'Joomla', r'option=com_',
                    r'media/jui', r'media/system', r'JText._'
                ]},
                'magento': {'name': 'Magento', 'category': 'cms_platforms', 'patterns': [
                    r'magento', r'Mage.Cookies', r'skin/frontend', r'js/mage',
                    r'mage/cookies', r'Magento_', r'var/view_preprocessed'
                ]},
                'shopify': {'name': 'Shopify', 'category': 'cms_platforms', 'patterns': [
                    r'shopify', r'shop.js', r'Shopify.theme', r'cdn.shopify.com',
                    r'shopify-features', r'Shopify.Checkout', r'shopify_pay'
                ]},
                'prestashop': {'name': 'PrestaShop', 'category': 'cms_platforms', 'patterns': [
                    r'prestashop', r'PrestaShop', r'ps_version', r'prestashop.com'
                ]},
                'opencart': {'name': 'OpenCart', 'category': 'cms_platforms', 'patterns': [
                    r'opencart', r'OpenCart', r'catalog/view/javascript'
                ]},
                'woocommerce': {'name': 'WooCommerce', 'category': 'cms_platforms', 'patterns': [
                    r'woocommerce', r'WooCommerce', r'wc-', r'woocommerce.js'
                ]},
                'typo3': {'name': 'TYPO3', 'category': 'cms_platforms', 'patterns': [
                    r'typo3', r'TYPO3', r'typo3temp', r'ext_emconf.php'
                ]},
                'concrete5': {'name': 'Concrete5', 'category': 'cms_platforms', 'patterns': [
                    r'concrete5', r'Concrete5', r'ccm_', r'concrete/js'
                ]},
                'ghost': {'name': 'Ghost', 'category': 'cms_platforms', 'patterns': [
                    r'ghost', r'Ghost', r'ghost-url', r'ghost.min.js'
                ]},
                'jekyll': {'name': 'Jekyll', 'category': 'cms_platforms', 'patterns': [
                    r'jekyll', r'Jekyll', r'Generated by Jekyll'
                ]},
                'hugo': {'name': 'Hugo', 'category': 'cms_platforms', 'patterns': [
                    r'hugo', r'Hugo', r'Generated by Hugo'
                ]},
                'gatsby': {'name': 'Gatsby', 'category': 'cms_platforms', 'patterns': [
                    r'gatsby', r'Gatsby', r'___gatsby', r'gatsby-focus-wrapper'
                ]},
                'hexo': {'name': 'Hexo', 'category': 'cms_platforms', 'patterns': [
                    r'hexo', r'Hexo', r'Generated by Hexo'
                ]},
                
                # Frontend Frameworks
                'react': {'name': 'React', 'category': 'frontend_frameworks', 'patterns': [
                    r'react', r'React', r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
                    r'react-dom', r'ReactDOM', r'data-reactroot', r'_reactInternalInstance'
                ]},
                'vue': {'name': 'Vue.js', 'category': 'frontend_frameworks', 'patterns': [
                    r'vue', r'Vue', r'__VUE__', r'v-for', r'v-if', r'v-model',
                    r'vue-router', r'vuex', r'data-v-'
                ]},
                'angular': {'name': 'Angular', 'category': 'frontend_frameworks', 'patterns': [
                    r'angular', r'ng-', r'Angular', r'__karma__',
                    r'angular-cli', r'ng-version', r'ngFor', r'ngIf', r'@angular'
                ]},
                'angularjs': {'name': 'AngularJS', 'category': 'frontend_frameworks', 'patterns': [
                    r'angularjs', r'AngularJS', r'ng-app', r'ng-controller',
                    r'angular.module', r'data-ng-'
                ]},
                'svelte': {'name': 'Svelte', 'category': 'frontend_frameworks', 'patterns': [
                    r'svelte', r'Svelte', r'svelte-', r'__svelte'
                ]},
                'ember': {'name': 'Ember.js', 'category': 'frontend_frameworks', 'patterns': [
                    r'ember', r'Ember', r'ember-cli', r'ember-application'
                ]},
                'backbone': {'name': 'Backbone.js', 'category': 'frontend_frameworks', 'patterns': [
                    r'backbone', r'Backbone', r'backbone.js'
                ]},
                'knockout': {'name': 'Knockout.js', 'category': 'frontend_frameworks', 'patterns': [
                    r'knockout', r'Knockout', r'data-bind', r'ko.observable'
                ]},
                'alpine': {'name': 'Alpine.js', 'category': 'frontend_frameworks', 'patterns': [
                    r'alpine', r'Alpine', r'x-data', r'x-show', r'@click'
                ]},
                
                # JavaScript Libraries
                'jquery': {'name': 'jQuery', 'category': 'javascript_libraries', 'patterns': [
                    r'jquery', r'jQuery', r'\$\(document\)\.ready',
                    r'jquery.min.js', r'jquery-ui', r'jQuery.fn.jquery'
                ]},
                'lodash': {'name': 'Lodash', 'category': 'javascript_libraries', 'patterns': [
                    r'lodash', r'Lodash', r'_.', r'lodash.min.js'
                ]},
                'underscore': {'name': 'Underscore.js', 'category': 'javascript_libraries', 'patterns': [
                    r'underscore', r'Underscore', r'underscore.js'
                ]},
                'moment': {'name': 'Moment.js', 'category': 'javascript_libraries', 'patterns': [
                    r'moment', r'Moment', r'moment.js', r'moment.min.js'
                ]},
                'd3': {'name': 'D3.js', 'category': 'javascript_libraries', 'patterns': [
                    r'd3', r'D3', r'd3.js', r'd3.min.js', r'd3.select'
                ]},
                'chart_js': {'name': 'Chart.js', 'category': 'javascript_libraries', 'patterns': [
                    r'chart.js', r'Chart.js', r'chartjs', r'chart.min.js'
                ]},
                'three_js': {'name': 'Three.js', 'category': 'javascript_libraries', 'patterns': [
                    r'three.js', r'Three.js', r'three.min.js', r'THREE.'
                ]},
                'gsap': {'name': 'GSAP', 'category': 'javascript_libraries', 'patterns': [
                    r'gsap', r'GSAP', r'TweenMax', r'TweenLite', r'gsap.min.js'
                ]},
                'aos': {'name': 'AOS', 'category': 'javascript_libraries', 'patterns': [
                    r'aos', r'AOS', r'data-aos', r'aos.js'
                ]},
                'swiper': {'name': 'Swiper', 'category': 'javascript_libraries', 'patterns': [
                    r'swiper', r'Swiper', r'swiper-slide', r'swiper.min.js'
                ]},
                'owl_carousel': {'name': 'Owl Carousel', 'category': 'javascript_libraries', 'patterns': [
                    r'owl.carousel', r'OwlCarousel', r'owl-carousel'
                ]},
                'slick': {'name': 'Slick Slider', 'category': 'javascript_libraries', 'patterns': [
                    r'slick', r'Slick', r'slick.js', r'slick-slide'
                ]},
                'datatables': {'name': 'DataTables', 'category': 'javascript_libraries', 'patterns': [
                    r'datatables', r'DataTables', r'jquery.dataTables'
                ]},
                'select2': {'name': 'Select2', 'category': 'javascript_libraries', 'patterns': [
                    r'select2', r'Select2', r'select2.min.js'
                ]},
                'axios': {'name': 'Axios', 'category': 'javascript_libraries', 'patterns': [
                    r'axios', r'Axios', r'axios.min.js'
                ]},
                'fetch': {'name': 'Fetch API', 'category': 'javascript_libraries', 'patterns': [
                    r'fetch\(', r'window.fetch'
                ]},
                
                # CSS Frameworks
                'bootstrap': {'name': 'Bootstrap', 'category': 'css_frameworks', 'patterns': [
                    r'bootstrap', r'Bootstrap', r'btn-', r'col-', r'container-fluid',
                    r'bootstrap.min.css', r'bootstrap.css'
                ]},
                'foundation': {'name': 'Foundation', 'category': 'css_frameworks', 'patterns': [
                    r'foundation', r'Foundation', r'foundation.css'
                ]},
                'bulma': {'name': 'Bulma', 'category': 'css_frameworks', 'patterns': [
                    r'bulma', r'Bulma', r'bulma.css', r'is-primary'
                ]},
                'tailwind': {'name': 'Tailwind CSS', 'category': 'css_frameworks', 'patterns': [
                    r'tailwind', r'Tailwind', r'tailwindcss', r'tw-'
                ]},
                'semantic_ui': {'name': 'Semantic UI', 'category': 'css_frameworks', 'patterns': [
                    r'semantic', r'Semantic', r'semantic.css', r'ui segment'
                ]},
                'materialize': {'name': 'Materialize', 'category': 'css_frameworks', 'patterns': [
                    r'materialize', r'Materialize', r'materialize.css'
                ]},
                'uikit': {'name': 'UIkit', 'category': 'css_frameworks', 'patterns': [
                    r'uikit', r'UIkit', r'uikit.css', r'uk-'
                ]},
                'pure_css': {'name': 'Pure CSS', 'category': 'css_frameworks', 'patterns': [
                    r'purecss', r'Pure CSS', r'pure.css', r'pure-'
                ]},
                
                # Analytics & Tracking
                'google_analytics': {'name': 'Google Analytics', 'category': 'analytics_tools', 'patterns': [
                    r'google-analytics', r'ga\(', r'gtag\(', r'GoogleAnalyticsObject',
                    r'analytics.js', r'gtag/js', r'UA-\\d+-\\d+'
                ]},
                'gtm': {'name': 'Google Tag Manager', 'category': 'analytics_tools', 'patterns': [
                    r'googletagmanager', r'gtm.js', r'GTM-',
                    r'google.com/gtm/js', r'dataLayer'
                ]},
                'google_ads': {'name': 'Google Ads', 'category': 'analytics_tools', 'patterns': [
                    r'googleadservices', r'google.com/pagead', r'googlesyndication'
                ]},
                'facebook_pixel': {'name': 'Facebook Pixel', 'category': 'analytics_tools', 'patterns': [
                    r'fbq\(', r'facebook.com/tr', r'FacebookPixel'
                ]},
                'hotjar': {'name': 'Hotjar', 'category': 'analytics_tools', 'patterns': [
                    r'hotjar', r'Hotjar', r'static.hotjar.com'
                ]},
                'mixpanel': {'name': 'Mixpanel', 'category': 'analytics_tools', 'patterns': [
                    r'mixpanel', r'Mixpanel', r'mixpanel.com'
                ]},
                'segment': {'name': 'Segment', 'category': 'analytics_tools', 'patterns': [
                    r'segment', r'Segment', r'analytics.page', r'cdn.segment.com'
                ]},
                'adobe_analytics': {'name': 'Adobe Analytics', 'category': 'analytics_tools', 'patterns': [
                    r'adobe', r'Adobe', r'omniture', r's_code.js'
                ]},
                'yandex_metrica': {'name': 'Yandex Metrica', 'category': 'analytics_tools', 'patterns': [
                    r'yandex', r'Yandex', r'metrica', r'mc.yandex.ru'
                ]},
                
                # CDN Services
                'cloudflare': {'name': 'Cloudflare', 'category': 'cdn_services', 'patterns': [
                    r'cloudflare', r'__cf_bm', r'cf-ray', r'cdnjs.cloudflare.com'
                ]},
                'fastly': {'name': 'Fastly', 'category': 'cdn_services', 'patterns': [
                    r'fastly', r'fastly-debug', r'fastly.com'
                ]},
                'akamai': {'name': 'Akamai', 'category': 'cdn_services', 'patterns': [
                    r'akamai', r'akamaized', r'akamai.net'
                ]},
                'maxcdn': {'name': 'MaxCDN', 'category': 'cdn_services', 'patterns': [
                    r'maxcdn', r'MaxCDN', r'bootstrapcdn.com'
                ]},
                'jsdelivr': {'name': 'jsDelivr', 'category': 'cdn_services', 'patterns': [
                    r'jsdelivr', r'jsdelivr.net', r'cdn.jsdelivr.net'
                ]},
                'unpkg': {'name': 'UNPKG', 'category': 'cdn_services', 'patterns': [
                    r'unpkg', r'unpkg.com'
                ]},
                'cdnjs': {'name': 'CDNJS', 'category': 'cdn_services', 'patterns': [
                    r'cdnjs', r'cdnjs.com', r'cdnjs.cloudflare.com'
                ]},
                
                # E-commerce
                'stripe': {'name': 'Stripe', 'category': 'payment_gateways', 'patterns': [
                    r'stripe', r'Stripe', r'stripe.com', r'js.stripe.com'
                ]},
                'paypal': {'name': 'PayPal', 'category': 'payment_gateways', 'patterns': [
                    r'paypal', r'PayPal', r'paypal.com', r'paypalobjects.com'
                ]},
                'square': {'name': 'Square', 'category': 'payment_gateways', 'patterns': [
                    r'square', r'Square', r'squareup.com'
                ]},
                'braintree': {'name': 'Braintree', 'category': 'payment_gateways', 'patterns': [
                    r'braintree', r'Braintree', r'braintreepayments.com'
                ]},
                
                # Chat & Communication
                'intercom': {'name': 'Intercom', 'category': 'chat_systems', 'patterns': [
                    r'intercom', r'Intercom', r'intercom.io'
                ]},
                'zendesk': {'name': 'Zendesk', 'category': 'chat_systems', 'patterns': [
                    r'zendesk', r'Zendesk', r'zendesk.com'
                ]},
                'drift': {'name': 'Drift', 'category': 'chat_systems', 'patterns': [
                    r'drift', r'Drift', r'drift.com'
                ]},
                'livechat': {'name': 'LiveChat', 'category': 'chat_systems', 'patterns': [
                    r'livechat', r'LiveChat', r'livechatinc.com'
                ]},
                'crisp': {'name': 'Crisp', 'category': 'chat_systems', 'patterns': [
                    r'crisp', r'Crisp', r'crisp.chat'
                ]},
                'tawk': {'name': 'Tawk.to', 'category': 'chat_systems', 'patterns': [
                    r'tawk', r'Tawk', r'tawk.to'
                ]},
                
                # Monitoring & Performance
                'newrelic': {'name': 'New Relic', 'category': 'monitoring_tools', 'patterns': [
                    r'newrelic', r'New Relic', r'js-agent.newrelic.com'
                ]},
                'datadog': {'name': 'Datadog', 'category': 'monitoring_tools', 'patterns': [
                    r'datadog', r'Datadog', r'datadoghq.com'
                ]},
                'sentry': {'name': 'Sentry', 'category': 'monitoring_tools', 'patterns': [
                    r'sentry', r'Sentry', r'sentry.io'
                ]},
                'pingdom': {'name': 'Pingdom', 'category': 'monitoring_tools', 'patterns': [
                    r'pingdom', r'Pingdom', r'pingdom.net'
                ]},
                'bugsnag': {'name': 'Bugsnag', 'category': 'monitoring_tools', 'patterns': [
                    r'bugsnag', r'Bugsnag', r'bugsnag.com'
                ]},
                
                # Email Services
                'mailchimp': {'name': 'Mailchimp', 'category': 'email_services', 'patterns': [
                    r'mailchimp', r'Mailchimp', r'mailchimp.com'
                ]},
                'sendgrid': {'name': 'SendGrid', 'category': 'email_services', 'patterns': [
                    r'sendgrid', r'SendGrid', r'sendgrid.com'
                ]},
                'mailgun': {'name': 'Mailgun', 'category': 'email_services', 'patterns': [
                    r'mailgun', r'Mailgun', r'mailgun.com'
                ]},
                'campaign_monitor': {'name': 'Campaign Monitor', 'category': 'email_services', 'patterns': [
                    r'campaignmonitor', r'Campaign Monitor', r'createsend.com'
                ]},
                
                # Security & WAF
                'recaptcha': {'name': 'reCAPTCHA', 'category': 'security_technologies', 'patterns': [
                    r'recaptcha', r'reCAPTCHA', r'google.com/recaptcha'
                ]},
                'hcaptcha': {'name': 'hCaptcha', 'category': 'security_technologies', 'patterns': [
                    r'hcaptcha', r'hCaptcha', r'hcaptcha.com'
                ]},
                'turnstile': {'name': 'Cloudflare Turnstile', 'category': 'security_technologies', 'patterns': [
                    r'turnstile', r'Turnstile', r'challenges.cloudflare.com'
                ]},
            },
            'meta_tags': {
                'generator': {
                    'wordpress': {'name': 'WordPress', 'category': 'cms_platforms'},
                    'drupal': {'name': 'Drupal', 'category': 'cms_platforms'},
                    'joomla': {'name': 'Joomla', 'category': 'cms_platforms'},
                    'magento': {'name': 'Magento', 'category': 'cms_platforms'},
                    'shopify': {'name': 'Shopify', 'category': 'cms_platforms'},
                    'prestashop': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                    'opencart': {'name': 'OpenCart', 'category': 'cms_platforms'},
                    'typo3': {'name': 'TYPO3', 'category': 'cms_platforms'},
                    'concrete5': {'name': 'Concrete5', 'category': 'cms_platforms'},
                    'ghost': {'name': 'Ghost', 'category': 'cms_platforms'},
                    'jekyll': {'name': 'Jekyll', 'category': 'cms_platforms'},
                    'hugo': {'name': 'Hugo', 'category': 'cms_platforms'},
                    'gatsby': {'name': 'Gatsby', 'category': 'cms_platforms'},
                    'hexo': {'name': 'Hexo', 'category': 'cms_platforms'},
                    'nuxt': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
                    'next': {'name': 'Next.js', 'category': 'frontend_frameworks'},
                    'react': {'name': 'React', 'category': 'frontend_frameworks'},
                    'vue': {'name': 'Vue.js', 'category': 'frontend_frameworks'},
                    'angular': {'name': 'Angular', 'category': 'frontend_frameworks'},
                    'svelte': {'name': 'Svelte', 'category': 'frontend_frameworks'},
                    'ember': {'name': 'Ember.js', 'category': 'frontend_frameworks'},
                }
            },
            'cookies': {
                # Backend Technologies
                'PHPSESSID': {'name': 'PHP', 'category': 'backend_technologies'},
                'ASP.NET_SessionId': {'name': 'ASP.NET', 'category': 'backend_technologies'},
                'ASPSESSIONID': {'name': 'ASP Classic', 'category': 'backend_technologies'},
                'JSESSIONID': {'name': 'Java/J2EE', 'category': 'backend_technologies'},
                'connect.sid': {'name': 'Express.js', 'category': 'backend_technologies'},
                '_session_id': {'name': 'Ruby on Rails', 'category': 'backend_technologies'},
                'rack.session': {'name': 'Rack (Ruby)', 'category': 'backend_technologies'},
                'laravel_session': {'name': 'Laravel', 'category': 'backend_technologies'},
                'symfony': {'name': 'Symfony', 'category': 'backend_technologies'},
                'django_session': {'name': 'Django', 'category': 'backend_technologies'},
                'sessionid': {'name': 'Django', 'category': 'backend_technologies'},
                'flask-session': {'name': 'Flask', 'category': 'backend_technologies'},
                'beaker.session': {'name': 'Beaker (Python)', 'category': 'backend_technologies'},
                'spring': {'name': 'Spring Framework', 'category': 'backend_technologies'},
                'play_session': {'name': 'Play Framework', 'category': 'backend_technologies'},
                
                # CMS Platforms
                'wp-settings': {'name': 'WordPress', 'category': 'cms_platforms'},
                'wordpress_': {'name': 'WordPress', 'category': 'cms_platforms'},
                'SESS': {'name': 'Drupal', 'category': 'cms_platforms'},
                'drupal_session': {'name': 'Drupal', 'category': 'cms_platforms'},
                'frontend': {'name': 'Magento', 'category': 'cms_platforms'},
                'adminhtml': {'name': 'Magento', 'category': 'cms_platforms'},
                '_shopify_s': {'name': 'Shopify', 'category': 'cms_platforms'},
                '_shopify_y': {'name': 'Shopify', 'category': 'cms_platforms'},
                'PrestaShop': {'name': 'PrestaShop', 'category': 'cms_platforms'},
                'OCSESSID': {'name': 'OpenCart', 'category': 'cms_platforms'},
                'concrete5': {'name': 'Concrete5', 'category': 'cms_platforms'},
                'TYPO3_': {'name': 'TYPO3', 'category': 'cms_platforms'},
                'ghost-session': {'name': 'Ghost', 'category': 'cms_platforms'},
                
                # CDN/Cloud Services
                '__cfduid': {'name': 'Cloudflare', 'category': 'cdn_services'},
                'cf_clearance': {'name': 'Cloudflare', 'category': 'cdn_services'},
                '__cf_bm': {'name': 'Cloudflare', 'category': 'cdn_services'},
                'akamai': {'name': 'Akamai', 'category': 'cdn_services'},
                'fastly': {'name': 'Fastly', 'category': 'cdn_services'},
                
                # Analytics & Tracking
                '_ga': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gid': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gat': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                '_gtag': {'name': 'Google Analytics', 'category': 'analytics_tools'},
                'fbp': {'name': 'Facebook Pixel', 'category': 'analytics_tools'},
                '_fbp': {'name': 'Facebook Pixel', 'category': 'analytics_tools'},
                'fr': {'name': 'Facebook', 'category': 'analytics_tools'},
                'mp_': {'name': 'Mixpanel', 'category': 'analytics_tools'},
                'ajs_': {'name': 'Segment', 'category': 'analytics_tools'},
                '_hjid': {'name': 'Hotjar', 'category': 'analytics_tools'},
                '_hjSession': {'name': 'Hotjar', 'category': 'analytics_tools'},
                'AMCV_': {'name': 'Adobe Analytics', 'category': 'analytics_tools'},
                '_ym_': {'name': 'Yandex Metrica', 'category': 'analytics_tools'},
                
                # Security & WAF
                'incap_ses': {'name': 'Incapsula WAF', 'category': 'security_technologies'},
                'visid_incap': {'name': 'Incapsula WAF', 'category': 'security_technologies'},
                'sucuri': {'name': 'Sucuri WAF', 'category': 'security_technologies'},
                
                # E-commerce & Payment
                'stripe_mid': {'name': 'Stripe', 'category': 'payment_gateways'},
                'stripe_sid': {'name': 'Stripe', 'category': 'payment_gateways'},
                'paypal': {'name': 'PayPal', 'category': 'payment_gateways'},
                'PAYPAL_': {'name': 'PayPal', 'category': 'payment_gateways'},
                
                # Chat Systems
                'intercom-session': {'name': 'Intercom', 'category': 'chat_systems'},
                'intercom-id': {'name': 'Intercom', 'category': 'chat_systems'},
                'zendesk': {'name': 'Zendesk', 'category': 'chat_systems'},
                'drift': {'name': 'Drift', 'category': 'chat_systems'},
                'livechat': {'name': 'LiveChat', 'category': 'chat_systems'},
                'crisp-client': {'name': 'Crisp', 'category': 'chat_systems'},
                'tawk': {'name': 'Tawk.to', 'category': 'chat_systems'},
            },
            
            # File Fingerprints - MD5 hashes of common library files
            'file_hashes': {
                # jQuery versions
                '4f252523d4af0b478c810c2547a4bca5': {'name': 'jQuery', 'version': '3.6.0', 'category': 'javascript_libraries'},
                'a09e13ee94d51c524b7e2a728c7d4039': {'name': 'jQuery', 'version': '3.5.1', 'category': 'javascript_libraries'},
                'd6c9c9db4da9da9c1a6c55763b7321f2': {'name': 'jQuery', 'version': '3.4.1', 'category': 'javascript_libraries'},
                
                # Bootstrap versions
                '0e9b8cc1bd90a8de63d0b52b0c7a3bf1': {'name': 'Bootstrap', 'version': '5.1.3', 'category': 'css_frameworks'},
                '2e8b4d1c5c6a4a0fc8d5a2c2b8f9e3a4': {'name': 'Bootstrap', 'version': '4.6.0', 'category': 'css_frameworks'},
                
                # React versions
                'f1e9e3b4a2d4c5b6e7f8a9b0c1d2e3f4': {'name': 'React', 'version': '17.0.2', 'category': 'frontend_frameworks'},
                'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6': {'name': 'React', 'version': '18.2.0', 'category': 'frontend_frameworks'},
                
                # Vue.js versions
                'b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7': {'name': 'Vue.js', 'version': '3.2.37', 'category': 'frontend_frameworks'},
                'c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8': {'name': 'Vue.js', 'version': '2.6.14', 'category': 'frontend_frameworks'},
                
                # Angular versions
                'd4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9': {'name': 'Angular', 'version': '14.2.0', 'category': 'frontend_frameworks'},
                'e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0': {'name': 'Angular', 'version': '13.3.11', 'category': 'frontend_frameworks'},
            },
            
            # Additional Categories
            'databases': {
                'mysql': {'name': 'MySQL', 'category': 'databases'},
                'postgresql': {'name': 'PostgreSQL', 'category': 'databases'},
                'mongodb': {'name': 'MongoDB', 'category': 'databases'},
                'redis': {'name': 'Redis', 'category': 'databases'},
                'elasticsearch': {'name': 'Elasticsearch', 'category': 'databases'},
                'cassandra': {'name': 'Cassandra', 'category': 'databases'},
                'mariadb': {'name': 'MariaDB', 'category': 'databases'},
                'sqlite': {'name': 'SQLite', 'category': 'databases'},
                'oracle': {'name': 'Oracle Database', 'category': 'databases'},
                'mssql': {'name': 'Microsoft SQL Server', 'category': 'databases'},
            },
            
            'container_platforms': {
                'docker': {'name': 'Docker', 'category': 'container_platforms'},
                'kubernetes': {'name': 'Kubernetes', 'category': 'container_platforms'},
                'openshift': {'name': 'OpenShift', 'category': 'container_platforms'},
                'rancher': {'name': 'Rancher', 'category': 'container_platforms'},
                'nomad': {'name': 'HashiCorp Nomad', 'category': 'container_platforms'},
            },
            
            'message_queues': {
                'rabbitmq': {'name': 'RabbitMQ', 'category': 'message_queues'},
                'kafka': {'name': 'Apache Kafka', 'category': 'message_queues'},
                'activemq': {'name': 'Apache ActiveMQ', 'category': 'message_queues'},
                'zeromq': {'name': 'ZeroMQ', 'category': 'message_queues'},
                'amazon-sqs': {'name': 'Amazon SQS', 'category': 'message_queues'},
                'azure-servicebus': {'name': 'Azure Service Bus', 'category': 'message_queues'},
            }
        }
    
    def _init_file_fingerprints(self):
        """Inicializa database de fingerprints de arquivos."""
        self.file_fingerprints = {
            # Common JS/CSS file paths to check
            'common_files': [
                # Modern Frontend Frameworks
                '/_next/static/chunks/main.js',  # Next.js
                '/_nuxt/',  # Nuxt.js
                '/js/chunk-vendors.js',  # Vue CLI
                '/static/js/main.js',  # Create React App
                '/assets/index.js',  # Vite
                '/js/app.js',  # Laravel Mix
                
                # Traditional Libraries
                '/js/jquery.min.js',
                '/js/jquery.js',
                '/js/bootstrap.min.js',
                '/js/bootstrap.js',
                '/css/bootstrap.min.css',
                '/css/bootstrap.css',
                '/js/react.min.js',
                '/js/react.js',
                '/js/vue.min.js',
                '/js/vue.js',
                '/js/angular.min.js',
                '/js/angular.js',
                
                # Framework-specific assets
                '/assets/js/app.js',
                '/static/js/main.js',
                '/dist/js/main.js',
                '/build/static/js/main.js',
                
                # CMS Detection
                '/wp-includes/js/jquery/jquery.min.js',  # WordPress
                '/wp-content/themes/',  # WordPress
                '/wp-content/plugins/',  # WordPress
                '/sites/all/modules/',  # Drupal
                '/modules/system/system.js',  # Drupal
                '/media/system/js/core.js',  # Joomla
                '/administrator/templates/',  # Joomla
                '/skin/frontend/',  # Magento
                '/js/mage/',  # Magento
                '/assets/shopify_common.js',  # Shopify
                
                # Modern Build Tools
                '/webpack-runtime.js',
                '/vendor.js',
                '/manifest.js',
                '/.vite/',
                '/dist/assets/',
                
                # Common CDN patterns
                '/libs/',
                '/vendor/',
                '/node_modules/',
                
                # API/Service Workers
                '/sw.js',
                '/service-worker.js',
                '/workbox-sw.js'
            ]
        }
    
    def _calculate_file_hash(self, content):
        """Calcula hash MD5 do conteúdo do arquivo."""
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def _detect_from_file_hashes(self, url):
        """Detecta tecnologias através de fingerprinting de arquivos."""
        detections = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for file_path in self.file_fingerprints['common_files']:
                full_url = urljoin(url, file_path)
                future = executor.submit(self._check_file_hash, full_url)
                futures.append(future)
            
            for future in futures:
                result = future.result()
                if result:
                    detections.append(result)
        
        return detections
    
    def _check_file_hash(self, file_url):
        """Verifica hash e conteúdo de um arquivo específico."""
        try:
            response = self.session.get(file_url, timeout=5, verify=False)
            if response.status_code == 200:
                content = response.text
                file_hash = self._calculate_file_hash(content)
                
                # Check hash primeiro (mais preciso)
                if file_hash in self.tech_database['file_hashes']:
                    tech_info = self.tech_database['file_hashes'][file_hash]
                    return {
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': tech_info.get('version'),
                        'confidence': 99,
                        'source': f'File Hash: {file_url}'
                    }
                
                # Fallback: análise de conteúdo baseada no path
                return self._analyze_file_content(file_url, content)
            
            elif response.status_code == 403:
                # Arquivo existe mas está protegido - pode indicar tecnologia
                return self._analyze_file_access(file_url, response.text)
                
        except:
            pass
        return None
    
    def _analyze_file_content(self, file_url, content):
        """Analisa conteúdo de arquivo para detectar tecnologias."""
        content_lower = content.lower()
        
        # Padrões baseados no path e conteúdo
        detections = []
        
        # Next.js detection
        if '_next/' in file_url or 'next.js' in content_lower:
            detections.append({
                'name': 'Next.js',
                'category': 'frontend_frameworks',
                'version': None,
                'confidence': 85,
                'source': f'File Content: {file_url}'
            })
        
        # Nuxt.js detection
        elif '_nuxt/' in file_url or 'nuxt' in content_lower:
            detections.append({
                'name': 'Nuxt.js',
                'category': 'frontend_frameworks',
                'version': None,
                'confidence': 85,
                'source': f'File Content: {file_url}'
            })
        
        # Vue CLI detection
        elif 'chunk-vendors' in file_url or 'vue' in content_lower:
            detections.append({
                'name': 'Vue.js',
                'category': 'frontend_frameworks',
                'version': None,
                'confidence': 80,
                'source': f'File Content: {file_url}'
            })
        
        # Create React App detection
        elif ('static/js/main' in file_url or 'build/static' in file_url) and 'react' in content_lower:
            detections.append({
                'name': 'Create React App',
                'category': 'frontend_frameworks',
                'version': None,
                'confidence': 80,
                'source': f'File Content: {file_url}'
            })
        
        # Vite detection
        elif 'vite' in file_url or 'import.meta' in content_lower:
            detections.append({
                'name': 'Vite',
                'category': 'development_tools',
                'version': None,
                'confidence': 85,
                'source': f'File Content: {file_url}'
            })
        
        # Webpack detection
        elif 'webpack' in content_lower or '__webpack' in content_lower:
            detections.append({
                'name': 'Webpack',
                'category': 'development_tools',
                'version': None,
                'confidence': 85,
                'source': f'File Content: {file_url}'
            })
        
        # Service Worker detection
        elif ('sw.js' in file_url or 'service-worker' in file_url) and 'workbox' in content_lower:
            detections.append({
                'name': 'Workbox',
                'category': 'development_tools',
                'version': None,
                'confidence': 90,
                'source': f'File Content: {file_url}'
            })
        
        return detections[0] if detections else None
    
    def _analyze_file_access(self, file_url, content):
        """Analisa resposta 403 de arquivos específicos."""
        content_lower = content.lower()
        
        # WordPress protection patterns - deve ter evidência clara
        if ('wp-' in file_url and 'wordpress' in content_lower) or ('wp-content' in file_url and len(content) < 1000):
            # Baixa confiança para páginas genéricas de erro 403
            confidence = 40 if len(content) > 5000 else 80
            return {
                'name': 'WordPress',
                'category': 'cms_platforms',
                'version': None,
                'confidence': confidence,
                'source': f'Protected File: {file_url}'
            }
        
        # Drupal protection patterns - só se for URL específica do Drupal
        elif ('/sites/all/modules' in file_url or '/modules/system' in file_url) and len(content) < 1000:
            return {
                'name': 'Drupal',
                'category': 'cms_platforms',
                'version': None,
                'confidence': 80,
                'source': f'Protected File: {file_url}'
            }
        
        return None
    
    def _detect_passive_scan(self, base_url):
        """Realiza scan passivo em arquivos comuns."""
        detections = []
        passive_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/.well-known/security.txt',
            '/.htaccess',
            '/readme.txt',
            '/license.txt',
            '/changelog.txt',
            '/wp-config.php.bak',
            '/web.config',
            '/composer.json',
            '/package.json',
            '/.env',
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/admin/',
            '/administrator/',
            '/wp-admin/',
            '/wp-login.php',
            '/login.php',
            '/phpmyadmin/',
            '/mysql/',
            '/api/',
            '/v1/',
            '/graphql',
            '/swagger/',
            '/docs/',
            '/__docs__/',
            '/health',
            '/status',
            '/metrics'
        ]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            for file_path in passive_files:
                full_url = urljoin(base_url, file_path)
                future = executor.submit(self._check_passive_file, full_url)
                futures.append(future)
            
            for future in futures:
                result = future.result()
                if result:
                    detections.extend(result)
        
        return detections
    
    def _check_passive_file(self, file_url):
        """Verifica arquivo específico em scan passivo."""
        detections = []
        try:
            response = self.session.get(file_url, timeout=5, verify=False)
            content = response.text.lower()
            
            # Análise específica por tipo de arquivo
            if '/robots.txt' in file_url and response.status_code == 200:
                detections.extend(self._analyze_robots_txt(content))
            elif '/sitemap' in file_url and response.status_code == 200:
                detections.extend(self._analyze_sitemap(content))
            elif '/.well-known/security.txt' in file_url and response.status_code == 200:
                detections.extend(self._analyze_security_txt(content))
            elif '/package.json' in file_url and response.status_code == 200:
                detections.extend(self._analyze_package_json(content))
            elif '/composer.json' in file_url and response.status_code == 200:
                detections.extend(self._analyze_composer_json(content))
            elif response.status_code == 403:
                # Páginas 403 podem indicar tecnologias específicas
                detections.extend(self._analyze_403_page(content, file_url))
            elif response.status_code == 404:
                # Páginas 404 customizadas podem revelar tecnologias
                detections.extend(self._analyze_404_page(content))
                
        except:
            pass
        
        return detections
    
    def _analyze_robots_txt(self, content):
        """Analisa robots.txt para detectar tecnologias."""
        detections = []
        
        patterns = {
            'wordpress': [r'wp-admin', r'wp-content', r'wp-includes'],
            'drupal': [r'sites/', r'modules/', r'profiles/'],
            'joomla': [r'administrator/', r'components/', r'modules/'],
            'magento': [r'downloader/', r'app/', r'skin/'],
            'shopify': [r'shopify', r'cart', r'checkout'],
            'django': [r'admin/', r'static/', r'media/'],
            'rails': [r'assets/', r'public/'],
            'nextjs': [r'_next/', r'api/'],
            'nuxt': [r'_nuxt/', r'.nuxt/'],
            'gatsby': [r'___gatsby', r'static/']
        }
        
        for tech, tech_patterns in patterns.items():
            if any(re.search(pattern, content) for pattern in tech_patterns):
                tech_info = self._get_tech_info_by_key(tech)
                if tech_info:
                    detections.append({
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': None,
                        'confidence': 75,
                        'source': 'robots.txt analysis'
                    })
        
        return detections
    
    def _analyze_sitemap(self, content):
        """Analisa sitemap para detectar tecnologias."""
        detections = []
        
        if 'wordpress' in content or 'wp-content' in content:
            detections.append({
                'name': 'WordPress',
                'category': 'cms_platforms',
                'version': None,
                'confidence': 80,
                'source': 'Sitemap analysis'
            })
        
        return detections
    
    def _analyze_security_txt(self, content):
        """Analisa security.txt para detectar políticas de segurança."""
        detections = []
        
        if content:
            detections.append({
                'name': 'Security.txt',
                'category': 'security_technologies',
                'version': None,
                'confidence': 90,
                'source': 'Security.txt file'
            })
        
        return detections
    
    def _analyze_package_json(self, content):
        """Analisa package.json para detectar tecnologias Node.js."""
        detections = []
        
        try:
            import json
            data = json.loads(content)
            dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            
            for dep_name in dependencies:
                tech_info = self._map_npm_dependency(dep_name)
                if tech_info:
                    detections.append({
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': dependencies[dep_name].replace('^', '').replace('~', ''),
                        'confidence': 95,
                        'source': f'package.json: {dep_name}'
                    })
        except:
            pass
        
        return detections
    
    def _analyze_composer_json(self, content):
        """Analisa composer.json para detectar tecnologias PHP."""
        detections = []
        
        try:
            import json
            data = json.loads(content)
            dependencies = {**data.get('require', {}), **data.get('require-dev', {})}
            
            for dep_name in dependencies:
                tech_info = self._map_composer_dependency(dep_name)
                if tech_info:
                    detections.append({
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': dependencies[dep_name].replace('^', '').replace('~', ''),
                        'confidence': 95,
                        'source': f'composer.json: {dep_name}'
                    })
        except:
            pass
        
        return detections
    
    def _analyze_403_page(self, content, url):
        """Analisa páginas 403 para detectar tecnologias."""
        detections = []
        
        # Padrões específicos de tecnologias em páginas 403/bloqueio
        tech_patterns = {
            # Web Servers
            'nginx': {'name': 'Nginx', 'category': 'web_servers'},
            'apache': {'name': 'Apache HTTP Server', 'category': 'web_servers'},
            'iis': {'name': 'Microsoft IIS', 'category': 'web_servers'},
            'litespeed': {'name': 'LiteSpeed', 'category': 'web_servers'},
            
            # Cloud Services/CDN
            'vercel': {'name': 'Vercel', 'category': 'cloud_services'},
            'netlify': {'name': 'Netlify', 'category': 'cloud_services'},
            'cloudflare': {'name': 'Cloudflare', 'category': 'cdn_services'},
            'aws': {'name': 'Amazon AWS', 'category': 'cloud_services'},
            'azure': {'name': 'Microsoft Azure', 'category': 'cloud_services'},
            'google cloud': {'name': 'Google Cloud', 'category': 'cloud_services'},
            'heroku': {'name': 'Heroku', 'category': 'cloud_services'},
            'github pages': {'name': 'GitHub Pages', 'category': 'cloud_services'},
            'gitlab pages': {'name': 'GitLab Pages', 'category': 'cloud_services'},
            
            # Security/WAF
            'sucuri': {'name': 'Sucuri WAF', 'category': 'security_technologies'},
            'incapsula': {'name': 'Incapsula WAF', 'category': 'security_technologies'},
            'akamai': {'name': 'Akamai WAF', 'category': 'security_technologies'},
            'mod_security': {'name': 'ModSecurity', 'category': 'security_technologies'},
            
            # Frameworks/CMS indicators
            'wordpress': {'name': 'WordPress', 'category': 'cms_platforms'},
            'drupal': {'name': 'Drupal', 'category': 'cms_platforms'},
            'joomla': {'name': 'Joomla', 'category': 'cms_platforms'},
            'laravel': {'name': 'Laravel', 'category': 'backend_technologies'},
            'django': {'name': 'Django', 'category': 'backend_technologies'},
            'express': {'name': 'Express.js', 'category': 'backend_technologies'},
            'nextjs': {'name': 'Next.js', 'category': 'frontend_frameworks'},
            'nuxt': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
            
            # Load Balancers
            'haproxy': {'name': 'HAProxy', 'category': 'web_servers'},
            'traefik': {'name': 'Traefik', 'category': 'web_servers'},
            'envoy': {'name': 'Envoy Proxy', 'category': 'web_servers'}
        }
        
        for pattern, tech_info in tech_patterns.items():
            if pattern in content:
                detections.append({
                    'name': tech_info['name'],
                    'category': tech_info['category'],
                    'version': None,
                    'confidence': 75,
                    'source': f'403/Security page: {pattern}'
                })
        
        return detections
    
    def _analyze_404_page(self, content):
        """Analisa páginas 404 customizadas para detectar tecnologias."""
        detections = []
        
        # Detecta frameworks por páginas 404 customizadas
        patterns = {
            'rails': [r'rails', r'ruby on rails'],
            'django': [r'django', r'page not found'],
            'laravel': [r'laravel', r'whoops'],
            'symfony': [r'symfony', r'error 404'],
            'spring': [r'spring', r'whitelabel error page'],
            'express': [r'express', r'cannot get'],
            'flask': [r'flask', r'not found'],
            'fastapi': [r'fastapi', r'not found'],
            'nextjs': [r'this page could not be found', r'_next'],
            'nuxt': [r'this page could not be found', r'_nuxt'],
            'gatsby': [r'gatsby', r'___gatsby']
        }
        
        for tech_key, tech_patterns in patterns.items():
            if any(re.search(pattern, content, re.IGNORECASE) for pattern in tech_patterns):
                tech_info = self._get_tech_info_by_key(tech_key)
                if tech_info:
                    detections.append({
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': None,
                        'confidence': 65,
                        'source': '404 page analysis'
                    })
        
        return detections
    
    def _get_tech_info_by_key(self, tech_key):
        """Busca informações de tecnologia por chave."""
        # Busca em diferentes seções da database
        search_sections = ['html_content', 'meta_tags']
        
        for section in search_sections:
            if section in self.tech_database:
                if section == 'meta_tags':
                    for subsection in self.tech_database[section]:
                        if tech_key in self.tech_database[section][subsection]:
                            return self.tech_database[section][subsection][tech_key]
                else:
                    if tech_key in self.tech_database[section]:
                        return self.tech_database[section][tech_key]
        return None
    
    def _map_npm_dependency(self, dep_name):
        """Mapeia dependências npm para tecnologias conhecidas."""
        npm_mapping = {
            'react': {'name': 'React', 'category': 'frontend_frameworks'},
            'react-dom': {'name': 'React', 'category': 'frontend_frameworks'},
            'vue': {'name': 'Vue.js', 'category': 'frontend_frameworks'},
            '@vue/cli': {'name': 'Vue.js', 'category': 'frontend_frameworks'},
            'angular': {'name': 'Angular', 'category': 'frontend_frameworks'},
            '@angular/core': {'name': 'Angular', 'category': 'frontend_frameworks'},
            'svelte': {'name': 'Svelte', 'category': 'frontend_frameworks'},
            'next': {'name': 'Next.js', 'category': 'frontend_frameworks'},
            'nuxt': {'name': 'Nuxt.js', 'category': 'frontend_frameworks'},
            'gatsby': {'name': 'Gatsby', 'category': 'frontend_frameworks'},
            'express': {'name': 'Express.js', 'category': 'backend_technologies'},
            'fastify': {'name': 'Fastify', 'category': 'backend_technologies'},
            'koa': {'name': 'Koa.js', 'category': 'backend_technologies'},
            'jquery': {'name': 'jQuery', 'category': 'javascript_libraries'},
            'lodash': {'name': 'Lodash', 'category': 'javascript_libraries'},
            'axios': {'name': 'Axios', 'category': 'javascript_libraries'},
            'bootstrap': {'name': 'Bootstrap', 'category': 'css_frameworks'},
            'tailwindcss': {'name': 'Tailwind CSS', 'category': 'css_frameworks'},
            'bulma': {'name': 'Bulma', 'category': 'css_frameworks'},
            'd3': {'name': 'D3.js', 'category': 'javascript_libraries'},
            'chart.js': {'name': 'Chart.js', 'category': 'javascript_libraries'},
            'three': {'name': 'Three.js', 'category': 'javascript_libraries'},
            'gsap': {'name': 'GSAP', 'category': 'javascript_libraries'},
            'socket.io': {'name': 'Socket.IO', 'category': 'javascript_libraries'},
            'moment': {'name': 'Moment.js', 'category': 'javascript_libraries'},
            'dayjs': {'name': 'Day.js', 'category': 'javascript_libraries'},
        }
        
        return npm_mapping.get(dep_name.lower())
    
    def _map_composer_dependency(self, dep_name):
        """Mapeia dependências composer para tecnologias conhecidas."""
        composer_mapping = {
            'laravel/framework': {'name': 'Laravel', 'category': 'backend_technologies'},
            'symfony/symfony': {'name': 'Symfony', 'category': 'backend_technologies'},
            'symfony/framework-bundle': {'name': 'Symfony', 'category': 'backend_technologies'},
            'codeigniter/framework': {'name': 'CodeIgniter', 'category': 'backend_technologies'},
            'cakephp/cakephp': {'name': 'CakePHP', 'category': 'backend_technologies'},
            'yiisoft/yii2': {'name': 'Yii Framework', 'category': 'backend_technologies'},
            'phalcon/cphalcon': {'name': 'Phalcon', 'category': 'backend_technologies'},
            'zendframework/zendframework': {'name': 'Zend Framework', 'category': 'backend_technologies'},
            'laminas/laminas-mvc': {'name': 'Laminas', 'category': 'backend_technologies'},
            'slim/slim': {'name': 'Slim Framework', 'category': 'backend_technologies'},
            'silex/silex': {'name': 'Silex', 'category': 'backend_technologies'},
            'drupal/core': {'name': 'Drupal', 'category': 'cms_platforms'},
            'drupal/drupal': {'name': 'Drupal', 'category': 'cms_platforms'},
            'magento/magento2-base': {'name': 'Magento', 'category': 'cms_platforms'},
            'october/october': {'name': 'October CMS', 'category': 'cms_platforms'},
            'concrete5/concrete5': {'name': 'Concrete5', 'category': 'cms_platforms'},
            'typo3/cms': {'name': 'TYPO3', 'category': 'cms_platforms'},
        }
        
        return composer_mapping.get(dep_name.lower())
    
    def _detect_from_headers(self, headers):
        """Detecta tecnologias a partir dos cabeçalhos HTTP."""
        detections = []
        
        for header_name, technologies in self.tech_database['headers'].items():
            header_value = headers.get(header_name, '').lower()
            if header_value:
                for tech_key, tech_info in technologies.items():
                    if tech_key in header_value:
                        version = None
                        if tech_info['version_regex']:
                            match = re.search(tech_info['version_regex'], header_value, re.IGNORECASE)
                            if match:
                                version = match.group(1)
                        
                        detection = {
                            'name': tech_info['name'],
                            'category': tech_info['category'],
                            'version': version,
                            'confidence': 95,
                            'source': f'HTTP Header: {header_name}'
                        }
                        detections.append(detection)
        
        return detections
    
    def _detect_from_html(self, html_content):
        """Detecta tecnologias a partir do conteúdo HTML."""
        detections = []
        
        # Verifica se é uma página de checkpoint/bloqueio (baixa confiabilidade)
        is_checkpoint = any(keyword in html_content.lower() for keyword in [
            'security checkpoint', 'vercel security', 'checking browser',
            'browser verification', 'please wait', 'loading...', 'redirect'
        ])
        
        # Detecta por padrões no HTML
        for tech_key, tech_info in self.tech_database['html_content'].items():
            for pattern in tech_info['patterns']:
                if re.search(pattern, html_content, re.IGNORECASE):
                    # Reduz confiança drasticamente se for página de checkpoint
                    confidence = 30 if is_checkpoint else 80
                    
                    detection = {
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': None,
                        'confidence': confidence,
                        'source': f'HTML Content: {pattern}' + (' (checkpoint page)' if is_checkpoint else '')
                    }
                    detections.append(detection)
                    break
        
        # Parse HTML para meta tags
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Meta generator
            generator_tag = soup.find('meta', attrs={'name': 'generator'})
            if generator_tag and generator_tag.get('content'):
                content = generator_tag['content'].lower()
                for tech_key, tech_info in self.tech_database['meta_tags']['generator'].items():
                    if tech_key in content:
                        version_match = re.search(r'([\\d\\.]+)', content)
                        version = version_match.group(1) if version_match else None
                        
                        detection = {
                            'name': tech_info['name'],
                            'category': tech_info['category'],
                            'version': version,
                            'confidence': 90,
                            'source': 'Meta Generator Tag'
                        }
                        detections.append(detection)
        except Exception as e:
            logger.error(f"Erro ao analisar HTML: {e}")
        
        return detections
    
    def _detect_from_cookies(self, cookies):
        """Detecta tecnologias a partir dos cookies."""
        detections = []
        
        for cookie in cookies:
            cookie_name = cookie.name.lower()
            for tech_cookie, tech_info in self.tech_database['cookies'].items():
                if tech_cookie.lower() in cookie_name:
                    detection = {
                        'name': tech_info['name'],
                        'category': tech_info['category'],
                        'version': None,
                        'confidence': 85,
                        'source': f'Cookie: {cookie.name}'
                    }
                    detections.append(detection)
        
        return detections
    
    def _detect_javascript_libraries(self, html_content):
        """Detecta bibliotecas JavaScript específicas."""
        detections = []
        
        # Padrões mais específicos para bibliotecas JS
        js_patterns = {
            'jquery': r'jquery[-.\\d]*\\.(?:min\\.)?js|jQuery\\.fn\\.jquery',
            'react': r'react[-.\\d]*\\.(?:min\\.)?js|React\\.version',
            'vue': r'vue[-.\\d]*\\.(?:min\\.)?js|Vue\\.version',
            'angular': r'angular[-.\\d]*\\.(?:min\\.)?js|angular\\.version',
            'bootstrap': r'bootstrap[-.\\d]*\\.(?:min\\.)?js|Bootstrap\\.version',
            'lodash': r'lodash[-.\\d]*\\.(?:min\\.)?js|_\\.VERSION',
            'moment': r'moment[-.\\d]*\\.(?:min\\.)?js|moment\\.version',
            'd3': r'd3[-.\\d]*\\.(?:min\\.)?js|d3\\.version',
            'chart.js': r'chart[-.\\d]*\\.(?:min\\.)?js|Chart\\.version',
            'axios': r'axios[-.\\d]*\\.(?:min\\.)?js|axios\\.VERSION',
        }
        
        for lib_name, pattern in js_patterns.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                detection = {
                    'name': lib_name.capitalize(),
                    'category': 'javascript_libraries',
                    'version': None,
                    'confidence': 75,
                    'source': f'JavaScript Pattern: {pattern}'
                }
                detections.append(detection)
        
        return detections
    
    def _detect_from_favicon(self, base_url: str) -> list:
        """Detecta tecnologias via hash do favicon (MurmurHash3 como Shodan/FOFA).

        Baixa `/favicon.ico`, calcula o MurmurHash3 do conteúdo em base64 e
        compara com hashes conhecidos de frameworks populares.

        Returns:
            Lista de detecções com name, category, confidence, favicon_hash.
        """
        import struct

        def _mmh3_32(data: bytes) -> int:
            """MurmurHash3 32-bit — algoritmo usado por Shodan para favicon."""
            seed = 0
            c1, c2 = 0xcc9e2d51, 0x1b873593
            length = len(data)
            h1 = seed
            blocks = length // 4
            for block_start in range(0, blocks * 4, 4):
                k1 = struct.unpack_from('<I', data, block_start)[0]
                k1 = (k1 * c1) & 0xFFFFFFFF
                k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
                k1 = (k1 * c2) & 0xFFFFFFFF
                h1 ^= k1
                h1 = (h1 << 13 | h1 >> 19) & 0xFFFFFFFF
                h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
            tail_start = blocks * 4
            tail = data[tail_start:]
            k1 = 0
            tail_size = length & 3
            if tail_size >= 3:
                k1 ^= tail[2] << 16
            if tail_size >= 2:
                k1 ^= tail[1] << 8
            if tail_size >= 1:
                k1 ^= tail[0]
                k1 = (k1 * c1) & 0xFFFFFFFF
                k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
                k1 = (k1 * c2) & 0xFFFFFFFF
                h1 ^= k1
            h1 ^= length
            h1 ^= h1 >> 16
            h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
            h1 ^= h1 >> 13
            h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
            h1 ^= h1 >> 16
            # Return as signed 32-bit integer (Shodan convention)
            return h1 - 0x100000000 if h1 >= 0x80000000 else h1

        # Hashes conhecidos: {mmh3_hash: (name, category, confidence)}
        FAVICON_HASHES = {
            -247388890:  ('Jenkins', 'ci_cd', 90),
            708578229:   ('GitLab', 'version_control', 90),
            -198605279:  ('Grafana', 'monitoring', 90),
            1659554838:  ('Kibana', 'analysis', 90),
            -1429180618: ('Elasticsearch', 'database', 85),
            -1180433470: ('Jira', 'project_management', 90),
            -1266444220: ('Confluence', 'wiki', 90),
            1278323558:  ('SonarQube', 'code_quality', 85),
            -1425565982: ('Portainer', 'containers', 85),
            -1616143435: ('Traefik', 'load_balancer', 85),
            1433191816:  ('Rancher', 'containers', 85),
            116323821:   ('Netdata', 'monitoring', 85),
            540343028:   ('phpMyAdmin', 'database_admin', 90),
            -961916748:  ('Nagios', 'monitoring', 85),
            1297690045:  ('Zabbix', 'monitoring', 85),
        }

        detections = []
        from urllib.parse import urljoin as _urljoin
        import base64 as _b64

        favicon_urls = [
            _urljoin(base_url, '/favicon.ico'),
            _urljoin(base_url, '/favicon.png'),
        ]

        for fav_url in favicon_urls:
            try:
                resp = self.session.get(fav_url, timeout=8, verify=False)
                if resp.status_code == 200 and resp.content:
                    # Shodan/FOFA: base64(content) com newlines cada 76 chars, then mmh3
                    b64_bytes = _b64.encodebytes(resp.content)
                    fav_hash = _mmh3_32(b64_bytes)
                    if fav_hash in FAVICON_HASHES:
                        name, category, confidence = FAVICON_HASHES[fav_hash]
                        detections.append({
                            'name': name,
                            'category': category,
                            'version': None,
                            'confidence': confidence,
                            'source': f'Favicon MurmurHash3: {fav_hash}',
                            'favicon_hash': fav_hash,
                        })
                    else:
                        # Include hash even if unknown — useful for threat intel
                        detections.append({
                            'name': f'Unknown (favicon hash: {fav_hash})',
                            'category': 'fingerprint',
                            'version': None,
                            'confidence': 30,
                            'source': 'Favicon MurmurHash3',
                            'favicon_hash': fav_hash,
                        })
                    break  # Stop after first successful favicon fetch
            except Exception:
                continue

        return detections

    def _detect_from_js_globals(self, html_content: str) -> list:
        """Detecta frameworks via variáveis globais JS no HTML da página.

        Inspeciona padrões inline como ``__NEXT_DATA__``, ``window.NUXT``,
        ``angular``, ``window.Ember``, ``Backbone``, etc.

        Returns:
            Lista de detecções com name, category, confidence.
        """
        detections = []

        # Padrões: (regex, name, category, confidence)
        GLOBAL_PATTERNS = [
            (r'__NEXT_DATA__', 'Next.js', 'frontend_frameworks', 95),
            (r'window\.__NUXT__', 'Nuxt.js', 'frontend_frameworks', 95),
            (r'window\.angular\b|angular\.module\b', 'AngularJS', 'frontend_frameworks', 90),
            (r'window\.Ember\b|Ember\.VERSION', 'Ember.js', 'frontend_frameworks', 90),
            (r'window\.Backbone\b|Backbone\.Model', 'Backbone.js', 'frontend_frameworks', 85),
            (r'window\._rails_env|window\.Rails\b', 'Ruby on Rails', 'web_frameworks', 85),
            (r'window\.RAILS_ENV', 'Ruby on Rails', 'web_frameworks', 80),
            (r'__GATSBY\b|___gatsby\b', 'Gatsby', 'static_site_generators', 95),
            (r'__REDUX_DEVTOOLS_EXTENSION__', 'Redux', 'frontend_frameworks', 80),
            (r'window\.dataLayer\b', 'Google Tag Manager', 'analytics', 90),
            (r'window\.ga\s*=|GoogleAnalyticsObject', 'Google Analytics', 'analytics', 90),
            (r'window\.fbq\b', 'Facebook Pixel', 'marketing', 85),
            (r'window\.Sentry\b|__SENTRY__', 'Sentry', 'monitoring', 90),
            (r'window\.mixpanel\b', 'Mixpanel', 'analytics', 85),
            (r'window\.Intercom\b', 'Intercom', 'customer_support', 90),
            (r'window\.HubSpotConversations\b', 'HubSpot', 'marketing', 90),
            (r'window\.LiveChatWidget\b', 'LiveChat', 'customer_support', 85),
            (r'window\.__APOLLO_CLIENT__', 'Apollo GraphQL', 'api', 90),
            (r'window\.Turbo\b', 'Hotwire Turbo', 'frontend_frameworks', 85),
        ]

        for pattern, name, category, confidence in GLOBAL_PATTERNS:
            if re.search(pattern, html_content, re.IGNORECASE):
                detections.append({
                    'name': name,
                    'category': category,
                    'version': None,
                    'confidence': confidence,
                    'source': f'JS Global: {pattern}',
                })

        return detections

    def _detect_cms_specifics(self, html_content, url):
        """Detecta CMS através de padrões específicos."""
        detections = []
        
        # WordPress
        wp_patterns = [
            r'/wp-content/',
            r'/wp-includes/',
            r'/wp-admin/',
            r'wp_enqueue_script',
            r'wp-json',
            r'WordPress'
        ]
        
        if any(re.search(pattern, html_content, re.IGNORECASE) for pattern in wp_patterns):
            # Tenta detectar versão do WordPress
            version_match = re.search(r'WordPress ([\\d\\.]+)', html_content)
            version = version_match.group(1) if version_match else None
            
            detection = {
                'name': 'WordPress',
                'category': 'cms_platforms',
                'version': version,
                'confidence': 95,
                'source': 'WordPress-specific patterns'
            }
            detections.append(detection)
        
        return detections
    
    def detect_technologies(self, verbose=False, enable_passive_scan=True, enable_file_fingerprinting=True):
        """Detecta todas as tecnologias do site usando métodos avançados."""
        all_detections = []
        
        try:
            # Cache check
            cache_key = f"{self.url}_{enable_passive_scan}_{enable_file_fingerprinting}"
            if cache_key in self.cache:
                if verbose:
                    console.print(f"[*] Cache: Resultado encontrado para [cyan]{self.url}[/cyan]")
                return self.cache[cache_key]
            
            start_time = time.time()
            
            # Faz requisição inicial com análise de tempo de resposta
            if verbose:
                console.print(f"[*] Alvo: [cyan]{self.url}[/cyan]")
                console.print(f"[*] Iniciando detecção de tecnologias...")
            
            response = self.session.get(self.url, timeout=self.timeout, verify=False)
            response_time = time.time() - start_time
            html_content = response.text
            
            # Detecta por diferentes métodos em paralelo usando ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Análise básica (sempre executada)
                basic_futures = {
                    'headers': executor.submit(self._detect_from_headers, response.headers),
                    'html': executor.submit(self._detect_from_html, html_content),
                    'cookies': executor.submit(self._detect_from_cookies, response.cookies),
                    'js_libs': executor.submit(self._detect_javascript_libraries, html_content),
                    'js_globals': executor.submit(self._detect_from_js_globals, html_content),
                    'cms': executor.submit(self._detect_cms_specifics, html_content, self.url),
                    'favicon': executor.submit(self._detect_from_favicon, self.url),
                    'timing': executor.submit(self._analyze_response_timing, response_time, response.headers),
                    'waf': executor.submit(self._detect_waf_technologies, response.headers, html_content)
                }
                
                # Análise avançada (opcional)
                advanced_futures = {}
                if enable_passive_scan:
                    advanced_futures['passive'] = executor.submit(self._detect_passive_scan, self.url)
                
                if enable_file_fingerprinting:
                    advanced_futures['fingerprints'] = executor.submit(self._detect_from_file_hashes, self.url)
                
                # API fingerprinting
                advanced_futures['api'] = executor.submit(self._detect_api_endpoints, self.url)
                
                # Coleta resultados básicos
                for detection_type, future in basic_futures.items():
                    try:
                        detections = future.result(timeout=30)
                        if detections:
                            all_detections.extend(detections)
                        if verbose:
                            console.print(f"[*] {detection_type.title()}: [cyan]{len(detections)}[/cyan] detecções")
                    except Exception as e:
                        if verbose:
                            console.print(f"[bold yellow][!] Erro em {detection_type}: {e}[/bold yellow]")
                        logger.warning(f"Erro em {detection_type}: {e}")
                
                # Coleta resultados avançados
                for detection_type, future in advanced_futures.items():
                    try:
                        detections = future.result(timeout=60)
                        if detections:
                            all_detections.extend(detections)
                        if verbose:
                            console.print(f"[*] {detection_type.title()}: [cyan]{len(detections)}[/cyan] detecções")
                    except Exception as e:
                        if verbose:
                            console.print(f"[bold yellow][!] Erro em {detection_type}: {e}[/bold yellow]")
                        logger.warning(f"Erro em análise avançada {detection_type}: {e}")
            
            # Remove duplicatas com priorização por confiança
            unique_detections = self._deduplicate_detections(all_detections)
            
            # Organiza por categoria
            for detection in unique_detections:
                category = detection['category']
                if category in self.detections:
                    self.detections[category].append(detection)
            
            # Adiciona métricas de performance
            total_time = time.time() - start_time
            self.detections['scan_metrics'] = [{
                'total_detections': len(unique_detections),
                'scan_time': round(total_time, 2),
                'response_time': round(response_time, 3),
                'methods_used': len(basic_futures) + len(advanced_futures),
                'cache_hit': False
            }]
            
            # Cache o resultado
            self.cache[cache_key] = self.detections.copy()
            
            if verbose:
                console.print(f"[*] Detecção concluída em [cyan]{total_time:.2f}s[/cyan]")
            
            return self.detections
            
        except requests.RequestException as e:
            logger.error(f"Erro ao detectar tecnologias: {e}")
            console.print(f"[bold red][!] Erro ao conectar com {self.url}: {e}[/bold red]")
            return self.detections
        
        except Exception as e:
            logger.error(f"Erro inesperado na detecção: {e}")
            console.print(f"[bold red][!] Erro inesperado: {e}[/bold red]")
            return self.detections
    
    def _deduplicate_detections(self, detections):
        """Remove duplicatas priorizando por confiança e qualidade da fonte."""
        seen = {}
        
        # Ranking de qualidade das fontes (maior = melhor)
        source_quality = {
            'File Hash': 100,
            'Meta Generator': 90,
            'Server Header': 85,
            'Response Headers': 80,
            'HTML Content': 75,
            'File Content': 70,
            'JavaScript Pattern': 65,
            '403/Security page': 60,
            'Protected File': 55,
            'WAF Pattern': 50,
            'Cookie': 45,
            'API Response': 40,
            'Fast response time': 30
        }
        
        for detection in detections:
            key = (detection['name'].lower(), detection['category'])
            
            if key not in seen:
                seen[key] = detection
            else:
                current = seen[key]
                
                # Calcula score combinado (confiança + qualidade da fonte)
                current_source_key = current.get('source', '').split(':')[0].strip()
                new_source_key = detection.get('source', '').split(':')[0].strip()
                
                current_score = current['confidence'] + source_quality.get(current_source_key, 0)
                new_score = detection['confidence'] + source_quality.get(new_source_key, 0)
                
                # Substitui se score for melhor
                if new_score > current_score:
                    seen[key] = detection
                elif new_score == current_score:
                    # Se scores iguais, prioriza quem tem versão
                    if detection.get('version') and not current.get('version'):
                        seen[key] = detection
        
        return list(seen.values())
    
    def _analyze_response_timing(self, response_time, headers):
        """Analisa tempo de resposta para inferir tecnologias."""
        detections = []
        
        # Tempos muito baixos podem indicar CDN/cache
        if response_time < 0.1:
            detections.append({
                'name': 'CDN/Cache Layer',
                'category': 'cdn_services',
                'version': None,
                'confidence': 60,
                'source': f'Fast response time: {response_time:.3f}s'
            })
        
        # Análise de headers de cache
        cache_headers = ['x-cache', 'x-cache-status', 'cf-cache-status', 'x-served-by']
        for header in cache_headers:
            if header in headers:
                if 'cloudflare' in headers[header].lower():
                    detections.append({
                        'name': 'Cloudflare',
                        'category': 'cdn_services',
                        'version': None,
                        'confidence': 85,
                        'source': f'Cache header: {header}'
                    })
                elif 'fastly' in headers[header].lower():
                    detections.append({
                        'name': 'Fastly',
                        'category': 'cdn_services',
                        'version': None,
                        'confidence': 85,
                        'source': f'Cache header: {header}'
                    })
        
        return detections
    
    def _detect_waf_technologies(self, headers, html_content):
        """Detecta tecnologias WAF/Firewall."""
        detections = []
        
        # Headers específicos de WAF
        waf_headers = {
            'cf-ray': {'name': 'Cloudflare WAF', 'category': 'security_technologies'},
            'x-sucuri-id': {'name': 'Sucuri WAF', 'category': 'security_technologies'},
            'x-incap-session': {'name': 'Incapsula WAF', 'category': 'security_technologies'},
            'x-akamai-edgescape': {'name': 'Akamai WAF', 'category': 'security_technologies'},
            'server-id': {'name': 'F5 BIG-IP', 'category': 'security_technologies'},
            'x-forwarded-for': {'name': 'Load Balancer/Proxy', 'category': 'security_technologies'},
            'x-real-ip': {'name': 'Reverse Proxy', 'category': 'security_technologies'},
        }
        
        for header_name, tech_info in waf_headers.items():
            if header_name in headers:
                detections.append({
                    'name': tech_info['name'],
                    'category': tech_info['category'],
                    'version': None,
                    'confidence': 90,
                    'source': f'WAF Header: {header_name}'
                })
        
        # Detecta WAF por padrões no HTML (páginas de bloqueio)
        waf_patterns = {
            'cloudflare': [r'cloudflare', r'ray id', r'cf-ray'],
            'incapsula': [r'incapsula', r'incap_ses'],
            'sucuri': [r'sucuri', r'access denied.*sucuri'],
            'akamai': [r'akamai', r'reference #'],
            'barracuda': [r'barracuda', r'blocked by barracuda'],
            'f5': [r'f5', r'big-ip', r'f5 networks'],
            'fortinet': [r'fortinet', r'fortigate'],
            'palo_alto': [r'palo alto', r'pan-os'],
        }
        
        content_lower = html_content.lower()
        for waf_name, patterns in waf_patterns.items():
            if any(re.search(pattern, content_lower) for pattern in patterns):
                detections.append({
                    'name': f'{waf_name.title()} WAF',
                    'category': 'security_technologies',
                    'version': None,
                    'confidence': 80,
                    'source': f'WAF Pattern: {waf_name}'
                })
        
        return detections
    
    def _detect_api_endpoints(self, base_url):
        """Detecta endpoints de API comuns."""
        detections = []
        
        api_endpoints = [
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/v1/',
            '/v2/',
            '/rest/',
            '/graphql',
            '/graphiql',
            '/swagger/',
            '/swagger.json',
            '/swagger.yaml',
            '/api-docs/',
            '/docs/',
            '/openapi.json',
            '/api/health',
            '/health',
            '/status',
            '/ping',
            '/metrics',
            '/actuator/',
        ]
        
        def check_endpoint(endpoint):
            try:
                full_url = urljoin(base_url, endpoint)
                response = self.session.head(full_url, timeout=5, verify=False)
                
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    if 'application/json' in content_type:
                        return {
                            'name': 'REST API',
                            'category': 'development_tools',
                            'version': None,
                            'confidence': 85,
                            'source': f'API Endpoint: {endpoint}'
                        }
                    elif 'graphql' in endpoint:
                        return {
                            'name': 'GraphQL',
                            'category': 'development_tools',
                            'version': None,
                            'confidence': 90,
                            'source': f'GraphQL Endpoint: {endpoint}'
                        }
                    elif 'swagger' in endpoint or 'openapi' in endpoint:
                        return {
                            'name': 'Swagger/OpenAPI',
                            'category': 'development_tools',
                            'version': None,
                            'confidence': 95,
                            'source': f'API Documentation: {endpoint}'
                        }
                    elif 'actuator' in endpoint:
                        return {
                            'name': 'Spring Boot Actuator',
                            'category': 'development_tools',
                            'version': None,
                            'confidence': 95,
                            'source': f'Actuator Endpoint: {endpoint}'
                        }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_endpoint, endpoint) for endpoint in api_endpoints]
            
            for future in futures:
                result = future.result()
                if result:
                    detections.append(result)
        
        return detections
    
    def present_results(self, output_format='table'):
        """Apresenta os resultados das detecções com múltiplos formatos."""
        if output_format == 'table':
            self._present_table_format()
        elif output_format == 'json':
            return self._export_json()
        elif output_format == 'xml':
            return self._export_xml()
        elif output_format == 'csv':
            return self._export_csv()
        elif output_format == 'html':
            return self._export_html()
        elif output_format == 'markdown':
            return self._export_markdown()
        else:
            console.print(f"[bold red]Formato não suportado: {output_format}[/bold red]")
            return None
        
        return self.detections
    
    def _present_table_format(self):
        """Apresenta resultados em formato de tabela seguindo padrão dos outros módulos."""
        console.print("-" * 60)
        console.print(f"[*] Tecnologias Detectadas: [bold cyan]{self.url}[/bold cyan]")
        console.print("-" * 60)
        
        # Mostra métricas de scan se disponíveis
        if 'scan_metrics' in self.detections:
            metrics = self.detections['scan_metrics'][0]
            console.print(f"[*] Scan concluído em [cyan]{metrics['scan_time']}s[/cyan] - [cyan]{metrics['total_detections']}[/cyan] tecnologias detectadas")
            console.print(f"[*] Tempo de resposta: [cyan]{metrics['response_time']}s[/cyan] - Métodos utilizados: [cyan]{metrics['methods_used']}[/cyan]")
            console.print("")
        
        total_detections = 0
        has_findings = False
        
        # Ordenar categorias por relevância
        category_order = {
            'cms_platforms': 1, 'backend_technologies': 2, 'frontend_frameworks': 3,
            'web_servers': 4, 'javascript_libraries': 5, 'css_frameworks': 6,
            'security_technologies': 7, 'cdn_services': 8, 'analytics_tools': 9,
            'databases': 10, 'cloud_services': 11
        }
        
        # Filtra detecções de baixa confiança (< 50%) e agrupa por categoria
        filtered_detections = {}
        for cat, detections in self.detections.items():
            if detections and cat != 'scan_metrics':
                # Filtra apenas detecções com confiança >= 50%
                high_confidence = [d for d in detections if d.get('confidence', 0) >= 50]
                if high_confidence:
                    filtered_detections[cat] = high_confidence
        
        sorted_categories = sorted(
            filtered_detections.items(),
            key=lambda x: category_order.get(x[0], 99)
        )
        
        for category, detections in sorted_categories:
            if detections:
                has_findings = True
                category_name = category.replace('_', ' ').title()
                console.print(f"")
                console.print(f"[*] {category_name}:")
                
                for detection in sorted(detections, key=lambda x: x['confidence'], reverse=True):
                    # Status baseado na confiança seguindo padrão dos outros módulos
                    version_info = f" v{detection['version']}" if detection.get('version') else ""
                    confidence_info = f" [cyan]({detection['confidence']}%)[/cyan]"
                    
                    console.print(f"[bold green][+] {detection['name']}{version_info}{confidence_info}[/bold green]")
                    
                    if detection.get('source'):
                        console.print(f"    [dim]└─ Detecção: {detection['source']}[/dim]")
                
                total_detections += len(detections)
        
        if not has_findings:
            console.print("[bold yellow][-] Nenhuma tecnologia específica foi detectada.[/bold yellow]")
        else:
            console.print(f"")
            console.print(f"[*] Total encontrado: [bold cyan]{total_detections}[/bold cyan] tecnologias")
        
        console.print("-" * 60)
    
    def _export_json(self):
        """Exporta resultados em formato JSON."""
        import json
        from datetime import datetime
        
        export_data = {
            'scan_info': {
                'target': self.url,
                'timestamp': datetime.now().isoformat(),
                'scanner': 'Spectra Advanced Technology Detector',
                'version': '2.0'
            },
            'technologies': self.detections
        }
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    
    def _export_xml(self):
        """Exporta resultados em formato XML."""
        from datetime import datetime
        from xml.sax.saxutils import escape
        
        xml_output = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_output.append('<technology_scan>')
        xml_output.append(f'  <scan_info>')
        xml_output.append(f'    <target>{escape(self.url)}</target>')
        xml_output.append(f'    <timestamp>{datetime.now().isoformat()}</timestamp>')
        xml_output.append(f'    <scanner>Spectra Advanced Technology Detector</scanner>')
        xml_output.append(f'  </scan_info>')
        xml_output.append('  <technologies>')
        
        for category, detections in self.detections.items():
            if detections and category != 'scan_metrics':
                xml_output.append(f'    <category name="{escape(category)}">')
                
                for detection in detections:
                    xml_output.append('      <technology>')
                    xml_output.append(f'        <name>{escape(detection["name"])}</name>')
                    xml_output.append(f'        <category>{escape(detection["category"])}</category>')
                    xml_output.append(f'        <version>{escape(str(detection.get("version", "")))}</version>')
                    xml_output.append(f'        <confidence>{detection["confidence"]}</confidence>')
                    xml_output.append(f'        <source>{escape(detection.get("source", ""))}</source>')
                    xml_output.append('      </technology>')
                
                xml_output.append('    </category>')
        
        xml_output.append('  </technologies>')
        xml_output.append('</technology_scan>')
        
        return '\\n'.join(xml_output)
    
    def _export_csv(self):
        """Exporta resultados em formato CSV."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['Name', 'Category', 'Version', 'Confidence', 'Source'])
        
        # Data
        for category, detections in self.detections.items():
            if detections and category != 'scan_metrics':
                for detection in detections:
                    writer.writerow([
                        detection['name'],
                        detection['category'],
                        detection.get('version', ''),
                        detection['confidence'],
                        detection.get('source', '')
                    ])
        
        return output.getvalue()
    
    def _export_html(self):
        """Exporta resultados em formato HTML."""
        from datetime import datetime
        
        html_template = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Tecnologias - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .metrics {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .category {{ margin-bottom: 30px; }}
        .category h2 {{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .tech-item {{ background: white; border: 1px solid #e9ecef; border-radius: 8px; padding: 15px; margin-bottom: 10px; }}
        .tech-name {{ font-weight: bold; font-size: 1.1em; color: #333; }}
        .tech-details {{ color: #666; margin-top: 5px; }}
        .confidence {{ padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
        .conf-high {{ background: #d4edda; color: #155724; }}
        .conf-medium {{ background: #fff3cd; color: #856404; }}
        .conf-low {{ background: #f8d7da; color: #721c24; }}
        .footer {{ text-align: center; padding: 20px; color: #666; border-top: 1px solid #e9ecef; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Relatório de Tecnologias</h1>
            <p>Análise completa de: <strong>{target}</strong></p>
            <p>Gerado em: {timestamp}</p>
        </div>
        
        <div class="content">
            {metrics_section}
            {categories_content}
        </div>
        
        <div class="footer">
            <p>Gerado por <strong>Spectra Advanced Technology Detector</strong></p>
        </div>
    </div>
</body>
</html>
        '''
        
        # Metrics section
        metrics_html = ""
        if 'scan_metrics' in self.detections:
            metrics = self.detections['scan_metrics'][0]
            metrics_html = f'''
            <div class="metrics">
                <h3>📊 Métricas de Scan</h3>
                <p><strong>Total de tecnologias:</strong> {metrics['total_detections']}</p>
                <p><strong>Tempo de scan:</strong> {metrics['scan_time']}s</p>
                <p><strong>Tempo de resposta:</strong> {metrics['response_time']}s</p>
                <p><strong>Métodos utilizados:</strong> {metrics['methods_used']}</p>
            </div>
            '''
        
        # Categories content
        categories_html = []
        for category, detections in self.detections.items():
            if detections and category != 'scan_metrics':
                category_name = category.replace('_', ' ').title()
                tech_items = []
                
                for detection in sorted(detections, key=lambda x: x['confidence'], reverse=True):
                    # Confidence class
                    if detection['confidence'] >= 90:
                        conf_class = "conf-high"
                    elif detection['confidence'] >= 70:
                        conf_class = "conf-medium"
                    else:
                        conf_class = "conf-low"
                    
                    version_info = f" v{detection['version']}" if detection.get('version') else ""
                    source_info = f"<br><small>Fonte: {detection.get('source', '')}</small>" if detection.get('source') else ""
                    
                    tech_items.append(f'''
                    <div class="tech-item">
                        <div class="tech-name">{detection['name']}{version_info}</div>
                        <div class="tech-details">
                            <span class="confidence {conf_class}">{detection['confidence']}% confiança</span>
                            {source_info}
                        </div>
                    </div>
                    ''')
                
                categories_html.append(f'''
                <div class="category">
                    <h2>{category_name} ({len(detections)})</h2>
                    {''.join(tech_items)}
                </div>
                ''')
        
        return html_template.format(
            target=self.url,
            timestamp=datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            metrics_section=metrics_html,
            categories_content=''.join(categories_html)
        )
    
    def _export_markdown(self):
        """Exporta resultados em formato Markdown."""
        from datetime import datetime
        
        markdown_output = []
        markdown_output.append(f"# 🔍 Relatório de Tecnologias")
        markdown_output.append(f"")
        markdown_output.append(f"**Target:** {self.url}")
        markdown_output.append(f"**Data:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        markdown_output.append(f"**Scanner:** Spectra Advanced Technology Detector v2.0")
        markdown_output.append(f"")
        
        # Metrics
        if 'scan_metrics' in self.detections:
            metrics = self.detections['scan_metrics'][0]
            markdown_output.append(f"## 📊 Métricas")
            markdown_output.append(f"")
            markdown_output.append(f"- **Total de tecnologias:** {metrics['total_detections']}")
            markdown_output.append(f"- **Tempo de scan:** {metrics['scan_time']}s")
            markdown_output.append(f"- **Tempo de resposta:** {metrics['response_time']}s")
            markdown_output.append(f"- **Métodos utilizados:** {metrics['methods_used']}")
            markdown_output.append(f"")
        
        # Technologies by category
        markdown_output.append(f"## 🛠️ Tecnologias Detectadas")
        markdown_output.append(f"")
        
        for category, detections in self.detections.items():
            if detections and category != 'scan_metrics':
                category_name = category.replace('_', ' ').title()
                markdown_output.append(f"### {category_name} ({len(detections)})")
                markdown_output.append(f"")
                
                for detection in sorted(detections, key=lambda x: x['confidence'], reverse=True):
                    # Confidence emoji
                    if detection['confidence'] >= 90:
                        conf_emoji = "🟢"
                    elif detection['confidence'] >= 70:
                        conf_emoji = "🟡"
                    else:
                        conf_emoji = "🔴"
                    
                    version_info = f" `v{detection['version']}`" if detection.get('version') else ""
                    markdown_output.append(f"- {conf_emoji} **{detection['name']}**{version_info} _{detection['confidence']}%_")
                    
                    if detection.get('source'):
                        markdown_output.append(f"  - Fonte: {detection['source']}")
                
                markdown_output.append(f"")
        
        return '\\n'.join(markdown_output)
    
    def save_report(self, filename, format='json'):
        """Salva relatório em arquivo seguindo padrão dos outros módulos."""
        try:
            content = self.present_results(output_format=format)
            
            if content:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                console.print(f"[bold green][+] Relatório salvo: {filename}[/bold green]")
                return True
            else:
                console.print(f"[bold red][!] Erro ao gerar conteúdo do relatório[/bold red]")
                return False
                
        except Exception as e:
            console.print(f"[bold red][!] Erro ao salvar relatório: {e}[/bold red]")
            return False

# Funções de compatibilidade legacy
def detect_technologies(url, verbose=False, output_format='table', enable_passive_scan=True, enable_file_fingerprinting=True):
    """Função de compatibilidade para detecção de tecnologias com recursos avançados."""
    detector = AdvancedTechnologyDetector(url)
    detections = detector.detect_technologies(
        verbose=verbose, 
        enable_passive_scan=enable_passive_scan,
        enable_file_fingerprinting=enable_file_fingerprinting
    )
    
    if output_format != 'raw':
        result = detector.present_results(output_format)
        if output_format != 'table' and result:
            return result
    
    return detections

def technology_detection_scan(url, verbose=False, output_format='table', **kwargs):
    """Função alternativa de compatibilidade com suporte a parâmetros avançados."""
    return detect_technologies(url, verbose=verbose, output_format=output_format, **kwargs)

def quick_tech_scan(url, verbose=False):
    """Scan rápido sem análise passiva ou fingerprinting."""
    return detect_technologies(
        url, 
        verbose=verbose, 
        output_format='table',
        enable_passive_scan=False,
        enable_file_fingerprinting=False
    )

def deep_tech_scan(url, verbose=True, save_report=None, report_format='html'):
    """Scan profundo com todas as funcionalidades ativadas."""
    detector = AdvancedTechnologyDetector(url)
    detections = detector.detect_technologies(
        verbose=verbose,
        enable_passive_scan=True,
        enable_file_fingerprinting=True
    )
    
    # Salva relatório se solicitado
    if save_report:
        detector.save_report(save_report, report_format)
    
    # Apresenta resultados na tela
    detector.present_results('table')
    
    return detections
