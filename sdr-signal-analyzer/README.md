# SDR Signal Analyzer

## 📡 Visão Geral

O **SDR Signal Analyzer** é uma plataforma profissional de análise de sinais de radiofrequência desenvolvida para engenheiros de RF, pesquisadores de segurança e profissionais de telecomunicações. Utilizando tecnologia Software Defined Radio (SDR), o sistema oferece capacidades avançadas de captura, análise e monitoramento de espectro em tempo real.

## 🎯 Funcionalidades Principais

### 📊 Análise de Espectro
- **Análise FFT em tempo real** com resolução configurável
- **Waterfall display** para visualização temporal do espectro
- **Detecção automática de sinais** com classificação por modulação
- **Medição de potência** e análise de largura de banda
- **Gravação e reprodução** de amostras IQ

### 🔍 Demodulação e Decodificação
- **AM/FM/SSB/CW** - Modulações analógicas tradicionais
- **FSK/PSK/QAM** - Modulações digitais modernas
- **POCSAG/FLEX** - Sistemas de paging
- **ADS-B** - Rastreamento de aeronaves
- **APRS** - Sistema de relatório de posição automático

### 🛡️ Monitoramento de Segurança
- **Detecção de jammers** e interferências maliciosas
- **Análise de protocolos IoT** (LoRa, Zigbee, 433MHz)
- **Monitoramento de frequências licenciadas** e não licenciadas
- **Detecção de dispositivos não autorizados** na rede RF
- **Análise forense** de transmissões suspeitas

### 📈 Relatórios e Alertas
- **Relatórios automatizados** de atividade do espectro
- **Alertas em tempo real** para atividades anômalas
- **Exportação de dados** em múltiplos formatos
- **Integração com SIEM** para correlação de eventos

## 🛠️ Stack Tecnológico

### Backend (Python)
- **GNU Radio 3.10+** - Framework principal SDR
- **PyQt6** - Interface gráfica moderna
- **NumPy/SciPy** - Processamento matemático e DSP
- **Matplotlib** - Visualização de dados científicos
- **SQLite** - Armazenamento de configurações e logs
- **asyncio** - Processamento assíncrono de sinais

### Hardware Suportado
- **RTL-SDR** (RTL2832U) - Receptor de baixo custo
- **HackRF One** - Transceptor full-duplex
- **USRP** (Ettus Research) - Plataforma profissional
- **BladeRF** - SDR de alta performance
- **LimeSDR** - SDR open-source avançado

### Protocolos e Padrões
- **IEEE 802.11** (WiFi) - Análise de redes sem fio
- **IEEE 802.15.4** (Zigbee) - Redes de sensores
- **LoRaWAN** - Redes LPWAN
- **GSM/LTE** - Comunicações celulares
- **TETRA/P25** - Comunicações de emergência

## 🚀 Instalação e Configuração

### Pré-requisitos
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install gnuradio gnuradio-dev gr-osmosdr
sudo apt install python3-pip python3-venv
sudo apt install librtlsdr-dev libhackrf-dev

# Drivers SDR
sudo apt install rtl-sdr hackrf libbladerf-dev
```

### Instalação
```bash
# Clonar repositório
git clone https://github.com/seu-usuario/sdr-signal-analyzer.git
cd sdr-signal-analyzer

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Instalar dependências
pip install -r requirements.txt

# Configurar dispositivos SDR
sudo usermod -a -G plugdev $USER
sudo udevadm control --reload-rules
```

### Configuração Inicial
```bash
# Executar configuração inicial
python setup.py configure

# Testar dispositivos SDR
python -m sdr_analyzer.tools.device_test

# Iniciar aplicação
python main.py
```

## 📁 Estrutura do Projeto

```
sdr-signal-analyzer/
├── src/
│   ├── core/                    # Núcleo do sistema
│   │   ├── sdr_controller.py    # Controle de dispositivos SDR
│   │   ├── signal_processor.py  # Processamento de sinais
│   │   └── spectrum_analyzer.py # Análise de espectro
│   ├── demodulators/           # Módulos de demodulação
│   │   ├── analog_demod.py     # AM/FM/SSB/CW
│   │   ├── digital_demod.py    # FSK/PSK/QAM
│   │   └── protocol_demod.py   # Protocolos específicos
│   ├── gui/                    # Interface gráfica
│   │   ├── main_window.py      # Janela principal
│   │   ├── spectrum_widget.py  # Widget de espectro
│   │   └── waterfall_widget.py # Widget waterfall
│   ├── analysis/               # Ferramentas de análise
│   │   ├── signal_classifier.py # Classificação automática
│   │   ├── interference_detector.py # Detecção de interferências
│   │   └── protocol_analyzer.py # Análise de protocolos
│   └── utils/                  # Utilitários
│       ├── config_manager.py   # Gerenciamento de configurações
│       ├── data_logger.py      # Log de dados
│       └── report_generator.py # Geração de relatórios
├── gnuradio/                   # Flowgraphs GNU Radio
│   ├── receivers/              # Receptores especializados
│   ├── analyzers/              # Analisadores de protocolo
│   └── tools/                  # Ferramentas auxiliares
├── configs/                    # Arquivos de configuração
├── data/                       # Dados e amostras
├── docs/                       # Documentação
└── tests/                      # Testes automatizados
```

## 🎛️ Módulos Principais

### SDR Controller
```python
from src.core.sdr_controller import SDRController

# Inicializar controlador
sdr = SDRController()
sdr.detect_devices()
sdr.set_device('rtlsdr')
```

## 🔧 Uso Profissional

### Análise de Segurança RF
- Monitoramento de espectro para detecção de ameaças
- Identificação de dispositivos não autorizados
- Análise forense de comunicações suspeitas

### Pesquisa e Desenvolvimento
- Prototipagem de sistemas de comunicação
- Teste de conformidade com padrões
- Análise de interferências eletromagnéticas

### Educação e Treinamento
- Laboratórios de engenharia de RF
- Demonstrações de conceitos SDR
- Análise prática de protocolos

## 📊 Métricas de Performance

- **Largura de banda**: Até 56 MHz (dependente do hardware)
- **Resolução de frequência**: 1 Hz - 1 MHz configurável
- **Sensibilidade**: -174 dBm/Hz (ruído térmico)
- **Faixa dinâmica**: >70 dB (RTL-SDR), >100 dB (USRP)
- **Taxa de amostragem**: Até 61.44 MSPS

## 🛡️ Considerações de Segurança

- **Conformidade regulatória** com normas locais de RF
- **Proteção de dados** sensíveis capturados
- **Controle de acesso** baseado em funções
- **Auditoria completa** de todas as operações
- **Criptografia** de dados armazenados

## 📚 Recursos Educacionais

- [Documentação Técnica Completa](docs/)
- [Tutoriais Passo-a-Passo](docs/tutorials/)
- [Exemplos de Código](examples/)
- [Casos de Uso Práticos](docs/use-cases/)
- [FAQ e Troubleshooting](docs/faq.md)

## 🤝 Contribuições

Contribuições são bem-vindas! Por favor, leia nosso [Guia de Contribuição](CONTRIBUTING.md) antes de submeter pull requests.

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 📞 Suporte

Para suporte técnico e questões:
- 📧 Email: suporte@sdr-analyzer.com
- 💬 Discord: [SDR Community](https://discord.gg/sdr-analyzer)
- 📖 Wiki: [Documentação Online](https://wiki.sdr-analyzer.com)

---

**Desenvolvido com ❤️ para a comunidade de segurança cibernética e RF**