#!/usr/bin/env python3
"""
IoT Security Analyzer - Main Application
Ferramenta profissional para análise de segurança e pentesting de dispositivos IoT
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash

# Importar módulos personalizados
from models.database import init_db, get_db_connection
from scanners.network_scanner import NetworkScanner
from scanners.bluetooth_scanner import BluetoothScanner
from scanners.wifi_scanner import WiFiScanner
from analyzers.vulnerability_analyzer import VulnerabilityAnalyzer
from analyzers.protocol_analyzer import ProtocolAnalyzer
from analyzers.firmware_analyzer import FirmwareAnalyzer
from reports.report_generator import ReportGenerator
from utils.config import Config
from utils.logger import setup_logger

# Configurar aplicação Flask
app = Flask(__name__)
app.config.from_object(Config)

# Configurar extensões
CORS(app, origins=['http://localhost:3000', 'http://127.0.0.1:3000'])
jwt = JWTManager(app)

# Configurar logging
logger = setup_logger(__name__)

# Inicializar serviços
network_scanner = NetworkScanner()
bluetooth_scanner = BluetoothScanner()
wifi_scanner = WiFiScanner()
vulnerability_analyzer = VulnerabilityAnalyzer()
protocol_analyzer = ProtocolAnalyzer()
firmware_analyzer = FirmwareAnalyzer()
report_generator = ReportGenerator()

@app.before_first_request
def initialize_database():
    """Inicializar banco de dados na primeira requisição"""
    init_db()
    logger.info("Banco de dados inicializado")

@app.route('/')
def index():
    """Página inicial da aplicação"""
    return render_template('index.html')

@app.route('/api/health')
def health_check():
    """Endpoint de verificação de saúde da aplicação"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    })

# ==================== AUTENTICAÇÃO ====================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Endpoint de autenticação"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username e password são obrigatórios'}), 400
        
        # Verificar credenciais (implementar com banco de dados real)
        if username == 'admin' and password == 'admin123':
            access_token = create_access_token(
                identity=username,
                expires_delta=timedelta(hours=24)
            )
            
            logger.info(f"Login realizado com sucesso para usuário: {username}")
            
            return jsonify({
                'access_token': access_token,
                'user': {
                    'username': username,
                    'role': 'admin'
                }
            })
        
        return jsonify({'error': 'Credenciais inválidas'}), 401
        
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

# ==================== NETWORK SCANNING ====================

@app.route('/api/scan/network', methods=['POST'])
@jwt_required()
def scan_network():
    """Realizar scan de rede para descobrir dispositivos IoT"""
    try:
        data = request.get_json()
        target_network = data.get('network', '192.168.1.0/24')
        scan_type = data.get('type', 'quick')
        
        logger.info(f"Iniciando scan de rede: {target_network}")
        
        # Executar scan
        devices = network_scanner.discover_devices(target_network, scan_type)
        
        # Analisar dispositivos encontrados
        results = []
        for device in devices:
            device_info = {
                'ip': device.ip,
                'mac': device.mac,
                'hostname': device.hostname,
                'manufacturer': device.manufacturer,
                'device_type': device.device_type,
                'open_ports': device.open_ports,
                'services': device.services,
                'os_guess': device.os_guess,
                'last_seen': device.last_seen.isoformat(),
                'risk_level': device.risk_level
            }
            results.append(device_info)
        
        logger.info(f"Scan concluído. {len(results)} dispositivos encontrados")
        
        return jsonify({
            'success': True,
            'devices': results,
            'scan_info': {
                'network': target_network,
                'type': scan_type,
                'timestamp': datetime.utcnow().isoformat(),
                'total_devices': len(results)
            }
        })
        
    except Exception as e:
        logger.error(f"Erro no scan de rede: {str(e)}")
        return jsonify({'error': f'Erro no scan de rede: {str(e)}'}), 500

@app.route('/api/scan/bluetooth', methods=['POST'])
@jwt_required()
def scan_bluetooth():
    """Realizar scan de dispositivos Bluetooth/BLE"""
    try:
        data = request.get_json()
        scan_duration = data.get('duration', 10)
        scan_ble = data.get('ble', True)
        
        logger.info(f"Iniciando scan Bluetooth (BLE: {scan_ble})")
        
        # Executar scan Bluetooth
        devices = bluetooth_scanner.scan_devices(scan_duration, scan_ble)
        
        results = []
        for device in devices:
            device_info = {
                'address': device.address,
                'name': device.name,
                'rssi': device.rssi,
                'device_type': device.device_type,
                'services': device.services,
                'manufacturer_data': device.manufacturer_data,
                'is_connectable': device.is_connectable,
                'security_issues': device.security_issues
            }
            results.append(device_info)
        
        logger.info(f"Scan Bluetooth concluído. {len(results)} dispositivos encontrados")
        
        return jsonify({
            'success': True,
            'devices': results,
            'scan_info': {
                'duration': scan_duration,
                'ble_enabled': scan_ble,
                'timestamp': datetime.utcnow().isoformat(),
                'total_devices': len(results)
            }
        })
        
    except Exception as e:
        logger.error(f"Erro no scan Bluetooth: {str(e)}")
        return jsonify({'error': f'Erro no scan Bluetooth: {str(e)}'}), 500

# ==================== VULNERABILITY ANALYSIS ====================

@app.route('/api/analyze/vulnerabilities', methods=['POST'])
@jwt_required()
def analyze_vulnerabilities():
    """Analisar vulnerabilidades em dispositivos"""
    try:
        data = request.get_json()
        target_ip = data.get('target_ip')
        analysis_type = data.get('type', 'comprehensive')
        
        if not target_ip:
            return jsonify({'error': 'IP do dispositivo é obrigatório'}), 400
        
        logger.info(f"Iniciando análise de vulnerabilidades: {target_ip}")
        
        # Executar análise
        vulnerabilities = vulnerability_analyzer.analyze_device(target_ip, analysis_type)
        
        results = {
            'target': target_ip,
            'analysis_type': analysis_type,
            'timestamp': datetime.utcnow().isoformat(),
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            vuln_info = {
                'cve_id': vuln.cve_id,
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'affected_service': vuln.affected_service,
                'exploit_available': vuln.exploit_available,
                'mitigation': vuln.mitigation
            }
            results['vulnerabilities'].append(vuln_info)
            total_score += vuln.cvss_score
        
        if vulnerabilities:
            results['risk_score'] = total_score / len(vulnerabilities)
        
        # Gerar recomendações
        results['recommendations'] = vulnerability_analyzer.generate_recommendations(vulnerabilities)
        
        logger.info(f"Análise concluída. {len(vulnerabilities)} vulnerabilidades encontradas")
        
        return jsonify({
            'success': True,
            'analysis': results
        })
        
    except Exception as e:
        logger.error(f"Erro na análise de vulnerabilidades: {str(e)}")
        return jsonify({'error': f'Erro na análise: {str(e)}'}), 500

# ==================== FIRMWARE ANALYSIS ====================

@app.route('/api/analyze/firmware', methods=['POST'])
@jwt_required()
def analyze_firmware():
    """Analisar firmware de dispositivos IoT"""
    try:
        if 'firmware' not in request.files:
            return jsonify({'error': 'Arquivo de firmware é obrigatório'}), 400
        
        firmware_file = request.files['firmware']
        if firmware_file.filename == '':
            return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
        
        # Salvar arquivo temporariamente
        temp_path = f"/tmp/{firmware_file.filename}"
        firmware_file.save(temp_path)
        
        logger.info(f"Iniciando análise de firmware: {firmware_file.filename}")
        
        # Executar análise
        analysis_result = firmware_analyzer.analyze_firmware(temp_path)
        
        results = {
            'filename': firmware_file.filename,
            'file_size': analysis_result.file_size,
            'file_type': analysis_result.file_type,
            'architecture': analysis_result.architecture,
            'endianness': analysis_result.endianness,
            'compression': analysis_result.compression,
            'filesystem': analysis_result.filesystem,
            'extracted_files': analysis_result.extracted_files,
            'vulnerabilities': analysis_result.vulnerabilities,
            'hardcoded_credentials': analysis_result.hardcoded_credentials,
            'crypto_keys': analysis_result.crypto_keys,
            'network_configs': analysis_result.network_configs,
            'security_score': analysis_result.security_score,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Limpar arquivo temporário
        os.remove(temp_path)
        
        logger.info(f"Análise de firmware concluída: {firmware_file.filename}")
        
        return jsonify({
            'success': True,
            'analysis': results
        })
        
    except Exception as e:
        logger.error(f"Erro na análise de firmware: {str(e)}")
        return jsonify({'error': f'Erro na análise de firmware: {str(e)}'}), 500

# ==================== REPORT GENERATION ====================

@app.route('/api/reports/generate', methods=['POST'])
@jwt_required()
def generate_report():
    """Gerar relatório de análise de segurança"""
    try:
        data = request.get_json()
        report_type = data.get('type', 'comprehensive')
        scan_results = data.get('scan_results', [])
        vulnerability_results = data.get('vulnerability_results', [])
        
        logger.info(f"Gerando relatório: {report_type}")
        
        # Gerar relatório
        report = report_generator.generate_report(
            report_type=report_type,
            scan_results=scan_results,
            vulnerability_results=vulnerability_results
        )
        
        return jsonify({
            'success': True,
            'report': {
                'id': report.id,
                'type': report.type,
                'generated_at': report.generated_at.isoformat(),
                'file_path': report.file_path,
                'summary': report.summary
            }
        })
        
    except Exception as e:
        logger.error(f"Erro na geração de relatório: {str(e)}")
        return jsonify({'error': f'Erro na geração de relatório: {str(e)}'}), 500

if __name__ == '__main__':
    # Configurar modo debug baseado na variável de ambiente
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info("Iniciando IoT Security Analyzer")
    logger.info(f"Modo debug: {debug_mode}")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_mode,
        threaded=True
    )