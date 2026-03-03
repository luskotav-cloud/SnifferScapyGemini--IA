import argparse
import json
import logging
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP
import google.generativeai as genai

# carrega variáveis do .env
load_dotenv()

# preset dos logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# variavel global
lista_com_jsons = []

# --- configuracao do gemini ---
def configurar_gemini():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.error("GEMINI_API_KEY não encontrada. Defina no arquivo .env ou como variável de ambiente.")
        raise EnvironmentError("GEMINI_API_KEY não definida.")
    genai.configure(api_key=api_key)
    modelo = genai.GenerativeModel("gemini-3-flash-preview")
    logger.info("Gemini configurado com sucesso.")
    return modelo

# --- analise dos pacotes via IA ---
def analisar_com_ia(modelo, pacotes: list) -> str:
    """
    Envia um resumo dos pacotes capturados para o Gemini
    e retorna uma análise de segurança em texto.
    """
    if not pacotes:
        return "Nenhum pacote para analisar."

    # monta um resumo compacto para não exceder o limite de tokens
    resumo = []
    for p in pacotes:
        resumo.append({
            "protocolo":   p.get("protocol"),
            "src_ip":      p.get("source_ip"),
            "dst_ip":      p.get("destination_ip"),
            "src_port":    p.get("source_port"),
            "dst_port":    p.get("destination_port"),
            "flags":       p.get("flags"),
            "payload_len": p.get("cabecalho"),
        })

    prompt = f"""
Você é um especialista em segurança de redes.
Abaixo está um conjunto de {len(resumo)} pacotes capturados em JSON.
Analise-os e responda:
1. Há algum padrão suspeito (ex: port scan, flood, conexões incomuns)?
2. Quais IPs de origem aparecem com mais frequência?
3. Quais protocolos dominam o tráfego?
4. Existe alguma recomendação de segurança com base nesses dados?

Pacotes:
{json.dumps(resumo, indent=2, ensure_ascii=False)}

Responda de forma clara e objetiva em português.
"""

    try:
        resposta = modelo.generate_content(prompt)
        return resposta.text
    except Exception as e:
        logger.error(f"Erro ao consultar a IA: {e}")
        return f"Erro na análise via IA: {e}"

# --- pacote ==> dicionario ---
def construcao_dicio(pacote):
    dados = {}

    # coloca o timestamp para analise
    dados["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    # verifica se o pacote utiliza a camada ip
    if IP in pacote:
        camada_ip = pacote[IP]
        dados["source_ip"] = camada_ip.src
        dados["destination_ip"] = camada_ip.dst

        # ve o tipo de pacote: tcp, udp ou outro
        if TCP in pacote:
            camada_trans = pacote[TCP]
            dados["protocol"] = "TCP"
            dados["source_port"] = camada_trans.sport
            dados["destination_port"] = camada_trans.dport
            dados["flags"] = str(camada_trans.flags)
            dados["cabecalho"] = len(pacote[TCP].payload)
        elif UDP in pacote:
            camada_trans = pacote[UDP]
            dados["protocol"] = "UDP"
            dados["source_port"] = camada_trans.sport
            dados["destination_port"] = camada_trans.dport
            dados["flags"] = "N/A"   # udp não tem flag
            dados["cabecalho"] = len(pacote[UDP].payload)
        else:
            dados["protocol"] = "IP"
            dados["source_port"] = "N/A"
            dados["destination_port"] = "N/A"
            dados["flags"] = "N/A"
            dados["cabecalho"] = len(camada_ip.payload)
    else:
        # sem camada IP (ex: ARP), salva o sumário
        dados["protocol"] = pacote.summary()
        dados["source_ip"] = "N/A"
        dados["destination_ip"] = "N/A"
        dados["source_port"] = "N/A"
        dados["destination_port"] = "N/A"
        dados["flags"] = "N/A"
        dados["cabecalho"] = len(pacote)

    return dados

# --- dicio ===> lista global ---
def listar_json(pacote):
    global lista_com_jsons

    try:
        dados_dicio = construcao_dicio(pacote)
        lista_com_jsons.append(dados_dicio)
        logger.info(
            f"Pacote processado e adicionado ({len(lista_com_jsons)}). "
            f"Protocolo: {dados_dicio.get('protocol', 'N/A')}."
        )
    except Exception as e:
        logger.error(f"Erro ao processar e adicionar pacote à lista: {e}")

# --- Lista + analise IA ==> Arquivo Final ---
def salvar_arquivo(caminho_arquivo, analise_ia: str = ""):
    global lista_com_jsons

    output_arg = Path(caminho_arquivo)

    try:
        output_arg.parent.mkdir(parents=True, exist_ok=True)

        # estrutura final: pacotes + analise da IA
        saida = {
            "total_pacotes": len(lista_com_jsons),
            "analise_ia": analise_ia,
            "pacotes": lista_com_jsons,
        }

        with open(output_arg, 'w', encoding='utf-8') as arquivo_final:
            json.dump(saida, arquivo_final, indent=4, ensure_ascii=False)

        logger.info(f"FIM DO SCRIPT. Dados salvos com sucesso em: {caminho_arquivo}")

    except Exception as e:
        logger.error(f"Erro ao salvar o arquivo JSON: {e}")


def main():
    opcoes = argparse.ArgumentParser(
        description="Coletor de Pacotes de Rede com análise de segurança via Google Gemini."
    )
    opcoes.add_argument(
        '--interface', '-i', type=str, required=True,
        help='Placa de rede para captura (ex: eth0).'
    )
    opcoes.add_argument(
        '--output', '-o', type=str, required=True,
        help='Caminho do arquivo JSON de saída (ex: saida.json).'
    )
    opcoes.add_argument(
        '--count', '-c', type=int, default=0,
        help='Quantidade de pacotes a capturar (0 = ilimitado).'
    )
    opcoes.add_argument(
        '--filter', '-f', type=str, default="",
        help='Filtro BPF (ex: "tcp port 80").'
    )
    opcoes.add_argument(
        '--no-ai', action='store_true',
        help='Desativa a análise via IA (útil para testes offline).'
    )

    args = opcoes.parse_args()

    # inicializa gemini (a menos que --no-ai seja passado)
    modelo_ia = None
    if not args.no_ai:
        try:
            modelo_ia = configurar_gemini()
        except EnvironmentError:
            logger.warning("Continuando sem análise de IA.")

    logger.info(f"Iniciando coleta na interface: {args.interface}")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            count=args.count,
            prn=listar_json,
            store=False
        )
        logger.info(
            f"Coleta finalizada. Total de {len(lista_com_jsons)} pacotes coletados."
        )

    except KeyboardInterrupt:
        logger.warning("Coleta interrompida pelo usuário (Ctrl+C). Salvando dados...")

    except PermissionError:
        logger.error("Permissão negada. Execute com privilégios de administrador (sudo/root).")
        return
    except ImportError:
        logger.error("Biblioteca 'scapy' não encontrada.")
        return
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        return

    # analise via IA
    analise = ""
    if modelo_ia and lista_com_jsons:
        logger.info("Enviando pacotes para análise via Gemini...")
        analise = analisar_com_ia(modelo_ia, lista_com_jsons)
        logger.info("Análise da IA concluída.")
        print("\n" + "="*60)
        print("ANÁLISE DE SEGURANÇA (Gemini):")
        print("="*60)
        print(analise)
        print("="*60 + "\n")

    salvar_arquivo(args.output, analise_ia=analise)


if __name__ == "__main__":
    main()
