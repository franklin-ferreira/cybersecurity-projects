#!/usr/bin/env python3
"""
SDR Signal Analyzer - Main Application
Aplicação principal para análise de sinais de radiofrequência usando SDR
"""

import sys
import os
import logging
import argparse
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QSplashScreen, QMessageBox
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QPixmap, QFont

# Adicionar diretório src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.gui.main_window import MainWindow
from src.core.sdr_controller import SDRController
from src.utils.config_manager import ConfigManager
from src.utils.logger_setup import setup_logger

class InitializationThread(QThread):
    """Thread para inicialização em background"""
    progress_updated = pyqtSignal(str, int)
    initialization_complete = pyqtSignal(bool, str)
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger(__name__)
    
    def run(self):
        """Executar inicialização em background"""
        try:
            # Etapa 1: Carregar configurações
            self.progress_updated.emit("Carregando configurações...", 20)
            config = ConfigManager()
            
            # Etapa 2: Verificar dispositivos SDR
            self.progress_updated.emit("Detectando dispositivos SDR...", 40)
            sdr_controller = SDRController()
            devices = sdr_controller.detect_devices()
            
            if not devices:
                self.logger.warning("Nenhum dispositivo SDR detectado")
                self.progress_updated.emit("Aviso: Nenhum dispositivo SDR detectado", 60)
            else:
                self.logger.info(f"Detectados {len(devices)} dispositivos SDR")
                self.progress_updated.emit(f"Detectados {len(devices)} dispositivos SDR", 60)
            
            # Etapa 3: Inicializar GNU Radio
            self.progress_updated.emit("Inicializando GNU Radio...", 80)
            
            # Etapa 4: Finalizar
            self.progress_updated.emit("Inicialização concluída!", 100)
            self.initialization_complete.emit(True, "Inicialização bem-sucedida")
            
        except Exception as e:
            self.logger.error(f"Erro na inicialização: {str(e)}")
            self.initialization_complete.emit(False, f"Erro na inicialização: {str(e)}")

class SDRAnalyzerApp:
    """Classe principal da aplicação SDR Signal Analyzer"""
    
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("SDR Signal Analyzer")
        self.app.setApplicationVersion("2.0.0")
        self.app.setOrganizationName("RF Security Labs")
        
        # Configurar logging
        self.logger = setup_logger(__name__)
        self.logger.info("Iniciando SDR Signal Analyzer v2.0.0")
        
        # Configurar estilo da aplicação
        self.setup_application_style()
        
        # Variáveis da aplicação
        self.main_window = None
        self.splash = None
        self.init_thread = None
    
    def setup_application_style(self):
        """Configurar estilo visual da aplicação"""
        # Definir fonte padrão
        font = QFont("Segoe UI", 9)
        self.app.setFont(font)
        
        # Aplicar tema escuro
        dark_stylesheet = """
        QMainWindow {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        
        QMenuBar {
            background-color: #3c3c3c;
            color: #ffffff;
            border-bottom: 1px solid #555555;
        }
        
        QMenuBar::item {
            background-color: transparent;
            padding: 4px 8px;
        }
        
        QMenuBar::item:selected {
            background-color: #555555;
        }
        
        QMenu {
            background-color: #3c3c3c;
            color: #ffffff;
            border: 1px solid #555555;
        }
        
        QMenu::item:selected {
            background-color: #555555;
        }
        
        QToolBar {
            background-color: #3c3c3c;
            border: none;
            spacing: 2px;
        }
        
        QToolButton {
            background-color: transparent;
            border: none;
            padding: 4px;
        }
        
        QToolButton:hover {
            background-color: #555555;
        }
        
        QStatusBar {
            background-color: #3c3c3c;
            color: #ffffff;
            border-top: 1px solid #555555;
        }
        
        QDockWidget {
            background-color: #2b2b2b;
            color: #ffffff;
            titlebar-close-icon: url(close.png);
            titlebar-normal-icon: url(undock.png);
        }
        
        QDockWidget::title {
            background-color: #3c3c3c;
            padding: 4px;
        }
        
        QTabWidget::pane {
            border: 1px solid #555555;
            background-color: #2b2b2b;
        }
        
        QTabBar::tab {
            background-color: #3c3c3c;
            color: #ffffff;
            padding: 8px 16px;
            margin-right: 2px;
        }
        
        QTabBar::tab:selected {
            background-color: #555555;
        }
        
        QGroupBox {
            color: #ffffff;
            border: 1px solid #555555;
            margin: 5px;
            padding-top: 10px;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        
        QPushButton {
            background-color: #4a4a4a;
            color: #ffffff;
            border: 1px solid #666666;
            padding: 6px 12px;
            border-radius: 3px;
        }
        
        QPushButton:hover {
            background-color: #555555;
        }
        
        QPushButton:pressed {
            background-color: #666666;
        }
        
        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
            background-color: #4a4a4a;
            color: #ffffff;
            border: 1px solid #666666;
            padding: 4px;
            border-radius: 2px;
        }
        
        QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
            border: 2px solid #0078d4;
        }
        
        QSlider::groove:horizontal {
            border: 1px solid #666666;
            height: 8px;
            background: #4a4a4a;
            margin: 2px 0;
            border-radius: 4px;
        }
        
        QSlider::handle:horizontal {
            background: #0078d4;
            border: 1px solid #0078d4;
            width: 18px;
            margin: -2px 0;
            border-radius: 9px;
        }
        
        QProgressBar {
            border: 1px solid #666666;
            border-radius: 5px;
            text-align: center;
            background-color: #4a4a4a;
        }
        
        QProgressBar::chunk {
            background-color: #0078d4;
            border-radius: 4px;
        }
        
        QSplitter::handle {
            background-color: #555555;
        }
        
        QSplitter::handle:horizontal {
            width: 3px;
        }
        
        QSplitter::handle:vertical {
            height: 3px;
        }
        """
        
        self.app.setStyleSheet(dark_stylesheet)
    
    def show_splash_screen(self):
        """Exibir tela de splash durante inicialização"""
        # Criar pixmap para splash screen
        splash_pixmap = QPixmap(400, 300)
        splash_pixmap.fill(Qt.GlobalColor.darkGray)
        
        # Criar splash screen
        self.splash = QSplashScreen(splash_pixmap)
        self.splash.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint)
        self.splash.show()
        
        # Mostrar mensagem inicial
        self.splash.showMessage(
            "SDR Signal Analyzer v2.0.0\nInicializando...",
            Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignBottom,
            Qt.GlobalColor.white
        )
        
        # Processar eventos para mostrar o splash
        self.app.processEvents()
    
    def start_initialization(self):
        """Iniciar processo de inicialização em background"""
        self.init_thread = InitializationThread()
        self.init_thread.progress_updated.connect(self.update_splash_message)
        self.init_thread.initialization_complete.connect(self.on_initialization_complete)
        self.init_thread.start()
    
    def update_splash_message(self, message, progress):
        """Atualizar mensagem do splash screen"""
        if self.splash:
            full_message = f"SDR Signal Analyzer v2.0.0\n{message}\n{progress}%"
            self.splash.showMessage(
                full_message,
                Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignBottom,
                Qt.GlobalColor.white
            )
            self.app.processEvents()
    
    def on_initialization_complete(self, success, message):
        """Callback para quando a inicialização for concluída"""
        if self.splash:
            self.splash.close()
        
        if success:
            self.logger.info("Inicialização concluída com sucesso")
            self.show_main_window()
        else:
            self.logger.error(f"Falha na inicialização: {message}")
            QMessageBox.critical(
                None,
                "Erro de Inicialização",
                f"Falha ao inicializar a aplicação:\n{message}"
            )
            sys.exit(1)
    
    def show_main_window(self):
        """Exibir janela principal da aplicação"""
        try:
            self.main_window = MainWindow()
            self.main_window.show()
            
            # Centralizar janela na tela
            screen = self.app.primaryScreen().geometry()
            window = self.main_window.geometry()
            x = (screen.width() - window.width()) // 2
            y = (screen.height() - window.height()) // 2
            self.main_window.move(x, y)
            
            self.logger.info("Janela principal exibida")
            
        except Exception as e:
            self.logger.error(f"Erro ao exibir janela principal: {str(e)}")
            QMessageBox.critical(
                None,
                "Erro",
                f"Erro ao exibir janela principal:\n{str(e)}"
            )
            sys.exit(1)
    
    def run(self):
        """Executar aplicação"""
        try:
            # Mostrar splash screen
            self.show_splash_screen()
            
            # Iniciar inicialização em background
            self.start_initialization()
            
            # Executar loop principal da aplicação
            return self.app.exec()
            
        except Exception as e:
            self.logger.error(f"Erro crítico na aplicação: {str(e)}")
            return 1

def parse_arguments():
    """Analisar argumentos da linha de comando"""
    parser = argparse.ArgumentParser(
        description="SDR Signal Analyzer - Plataforma de Análise RF",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Ativar modo debug com logging detalhado"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Caminho para arquivo de configuração personalizado"
    )
    
    parser.add_argument(
        "--device",
        type=str,
        help="Forçar uso de dispositivo SDR específico (rtlsdr, hackrf, usrp, etc.)"
    )
    
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="Executar em modo linha de comando (sem interface gráfica)"
    )
    
    return parser.parse_args()

def setup_logging(debug_mode=False):
    """Configurar sistema de logging"""
    log_level = logging.DEBUG if debug_mode else logging.INFO
    
    # Configurar formato de log
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Configurar logging para arquivo
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_dir / "sdr_analyzer.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Função principal"""
    # Analisar argumentos
    args = parse_arguments()
    
    # Configurar logging
    setup_logging(args.debug)
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 50)
    logger.info("SDR Signal Analyzer v2.0.0 - Iniciando")
    logger.info("=" * 50)
    
    try:
        if args.no_gui:
            logger.info("Modo linha de comando não implementado ainda")
            return 1
        else:
            # Executar aplicação com GUI
            app = SDRAnalyzerApp()
            return app.run()
            
    except KeyboardInterrupt:
        logger.info("Aplicação interrompida pelo usuário")
        return 0
    except Exception as e:
        logger.error(f"Erro crítico: {str(e)}")
        return 1
    finally:
        logger.info("SDR Signal Analyzer finalizado")

if __name__ == "__main__":
    sys.exit(main())