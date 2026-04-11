import os
import shutil
import tkinter as tk
from tkinter import messagebox
import requests
import xml.etree.ElementTree as ET
import threading
import time
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from tkinter import filedialog
import random
import queue

COR_FUNDO = "#1e1e2e"
COR_FRAME = "#2a2a3d"
COR_TEXTO = "#eaeaf0"   
COR_BOTAO = "#3b82f6" 

pasta_origem = 'docs'
xml_bruto = 'xml_bruto'
xml_lapidado = 'xml_lapidado'
xml_consumo_indevido = 'xml_consumo_indevido'
xml_invalido = 'xml_invalido'

os.makedirs(xml_bruto, exist_ok=True)
os.makedirs(xml_lapidado, exist_ok=True)
os.makedirs(xml_consumo_indevido, exist_ok=True)
os.makedirs(xml_invalido, exist_ok=True)


def limpar(xml):
    """Remove quebras de linha e BOM do XML."""
    return "".join(l.strip() for l in xml.lstrip("\ufeff").splitlines() if l.strip())

def fechar():
    janela_principal.destroy()


def remover_ns_signature(elem):
    for el in elem.iter():
        if isinstance(el.tag, str) and "http://www.w3.org/2000/09/xmldsig#" in el.tag:
            el.tag = el.tag.split('}', 1)[1]  # remove só o namespace da assinatura
    return elem



def xml_consulta(chave):
    """Gera XML de consulta de NFe."""
    return f"""
    <consSitNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">
        <tpAmb>1</tpAmb>
        <xServ>CONSULTAR</xServ>
        <chNFe>{chave}</chNFe>
    </consSitNFe>
    """.strip()


def montar_soap(xml_nfe):
    """Envolve o XML de consulta em SOAP."""
    return f"""
    <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
        <soap12:Body>
            <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4">
                {xml_nfe}
            </nfeDadosMsg>
        </soap12:Body>
    </soap12:Envelope>
    """.strip()


def extrair_prot(xml_retorno):
    """Extrai cStat, xMotivo, nProt e tpEmis do XML retornado da SEFAZ."""
    ns = {
        "soap": "http://www.w3.org/2003/05/soap-envelope",
        "nfe": "http://www.portalfiscal.inf.br/nfe",
        "ws": "http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4"
    }

    root = ET.fromstring(xml_retorno)

    ret = root.find(
        ".//ws:nfeResultMsg/nfe:retConsSitNFe",
        ns
    )

    if ret is None:
        return None
    
    infProt = ret.find(".//nfe:protNFe/nfe:infProt", ns)
    return {
        "cStat": ret.find("nfe:cStat", ns).text if ret.find("nfe:cStat", ns) is not None else None,
        "xMotivo": ret.find("nfe:xMotivo", ns).text if ret.find("nfe:xMotivo", ns) is not None else None,
        "nProt": infProt.find("nfe:nProt", ns).text if infProt is not None else None,
        "digVal": infProt.find("nfe:digVal", ns).text if infProt is not None and infProt.find("nfe:digVal", ns) is not None else None,
        "dhRecbto": infProt.find("nfe:dhRecbto", ns).text if infProt is not None and infProt.find("nfe:dhRecbto", ns) is not None else None,
        "verAplic": infProt.find("nfe:verAplic", ns).text if infProt is not None and infProt.find("nfe:verAplic", ns) is not None else None,
        "chNFe": ret.findtext("nfe:chNFe", default=None, namespaces=ns),
        "infProt": infProt is not None
    }

def load_pfx(pfx_path, password):
    """Carrega certificado PFX e retorna caminhos do PEM."""
    try:
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()
        private_key,certificate,additional_certs = pkcs12.load_key_and_certificates(pfx_data, password.encode())
        cert_pem = certificate.public_bytes(Encoding.PEM)

        with open("cert.pem","wb") as f:
            f.write(cert_pem)

        key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,NoEncryption())

        with open("key.pem","wb") as f:
            f.write(key_pem)

        return "cert.pem", "key.pem"  
    except Exception as erro:
        janela_validacao_xml.after(0,lambda e=erro: messagebox.showerror(f"Erro de certificado",{str(e)}))
        return None,None
    
  
fila = queue.Queue()

def espera_segura(falhas=0):
    base = 3
    max_time = 30

    delay = min(max_time, base * (2 ** falhas))
    jitter = random.uniform(0.5, 2.0)
    time.sleep(delay + jitter)


def carregar_fila(xml_bruto):
    for raiz, dirs, arquivos in os.walk(xml_bruto):
        for x in arquivos:
            fila.put((raiz, x))

ultimo_request = 0
def validar_xml(certificado, senha, xml_bruto, xml_saida):
    global ultimo_request   
    if not os.path.exists(xml_bruto):
        janela_validacao_xml.after(0, lambda: messagebox.showerror("Erro", "xml_bruto não encontrado!"))
        return

    if not os.path.exists(certificado):
        janela_validacao_xml.after(0, lambda: messagebox.showerror("Erro", "Certificado não encontrado!"))
        return
    
    if not os.path.exists(xml_saida):
        janela_validacao_xml.after(0, lambda: messagebox.showerror("Erro", "xml_lapidado não encontrado!"))
        return

    CERT_FILE, KEY_FILE = load_pfx(str(certificado).strip(), str(senha).strip())

    if CERT_FILE is None or KEY_FILE is None:
        return
    
    janela_validacao_xml.after(0, lambda: botao_validar_xml.config(state='disabled'))
    janela_validacao_xml.after(0, lambda: botao_voltar.config(state='disabled'))
    green = set()
    red = set()

    carregar_fila(xml_bruto)

    falhas_consecutivas = 0
    falhas_656 = 0

    while not fila.empty():
        intervalo_minimo = random.uniform(2.0, 5.0)
        janela_validacao_xml.after(0, lambda: campo_query99.insert(
            tk.END, "\n" + "*" * 30 + "\n", 'branco'
        ))

        raiz, x = fila.get()

        arquivo_completo = os.path.join(raiz, x)

        chave_modificada = x.removesuffix('-nfe.xml')
        chave_curta = chave_modificada[25:34].lstrip("0")

        saida = os.path.join(xml_saida, x)
        indevidos = os.path.join(xml_consumo_indevido, x)
        invalidos = os.path.join(xml_invalido, x)

        # -----------------------------
        # 1. Se já tem protocolo no XML e se já foi validada em outra chave anteriormente
        # -----------------------------
        try:
            ns = {"nfe": "http://www.portalfiscal.inf.br/nfe"}
            tree = ET.parse(arquivo_completo)
            root = tree.getroot()

            prot = root.find(".//nfe:protNFe", ns)

            if chave_curta in green:
                janela_validacao_xml.after(0, lambda: campo_query99.insert(
                    tk.END,
                    f"🟢 CHAVE {chave_modificada} IGNORADA POIS JÁ FOI ENCONTRADO XML CORRETO DE NUMERAÇÃO: {chave_curta}\n",
                    'amarelo'))
                continue

            if prot is not None:
                green.add(chave_curta)
                janela_validacao_xml.after(0, lambda: campo_query99.insert(
                    tk.END,
                    f"🟢 CHAVE {chave_modificada} VÁLIDADA DE NUMERAÇÃO: {chave_curta}\n",
                    'verde'
                ))
                shutil.copy2(arquivo_completo, saida)
                continue

        except Exception as e:
            janela_validacao_xml.after(0, lambda e=e: campo_query99.insert(tk.END, f"Erro XML: {e}\n", 'vermelho'))
            continue

        # -----------------------------
        # 2. Consulta SEFAZ
        # -----------------------------
        agora = time.time()
        tempo_passado = agora - ultimo_request
        if tempo_passado < intervalo_minimo:
            espera = max(0, intervalo_minimo - tempo_passado)
            time.sleep(espera)

        try:
            xml_nfe = limpar(xml_consulta(chave_modificada))
            soap_xml = montar_soap(xml_nfe)

            url = "https://nfce.fazenda.sp.gov.br/ws/NFeConsultaProtocolo4.asmx"
            headers = {"Content-Type": "application/soap+xml; charset=utf-8"}

            response = requests.post(
                url,
                data=soap_xml.encode("utf-8"),
                headers=headers,
                cert=(CERT_FILE, KEY_FILE),
                verify=False,
                timeout=(5, 15)
            )
            ultimo_request = time.time()

        except Exception as e:
            red.add(chave_curta)
            falhas_consecutivas += 1
            janela_validacao_xml.after(0, lambda e=e: campo_query99.insert(
                tk.END,
                f"Erro SEFAZ {chave_modificada}: {e}\n",
                'vermelho'
            ))

            espera_segura(min(falhas_consecutivas, 20))
            continue

        # -----------------------------
        # 3. Resposta SEFAZ
        # -----------------------------
        ret = extrair_prot(response.text)

        if not ret:
            red.add(chave_curta)
            falhas_consecutivas += 1
            espera_segura(min(falhas_consecutivas, 20))
            continue

        codigo = ret.get("cStat")
        motivo = ret.get("xMotivo")

        # -----------------------------
        # 4. Autorizado
        # -----------------------------
        if codigo == "100":
            falhas_consecutivas = 0
            falhas_656 = 0
            green.add(chave_curta)
            red.discard(chave_curta)
               
            janela_validacao_xml.after(0, lambda: campo_query99.insert(
                tk.END,
                f"🟢 CHAVE {chave_modificada} VÁLIDADA E PASSARÁ POR PROCESSO DE MONTAGEM DE XML: {chave_curta}\n",
                'rosa'
            ))

            try:
                ET.register_namespace('', "http://www.portalfiscal.inf.br/nfe")

                procNFe = ET.Element("nfeProc", attrib={"versao": "4.00"})
                nfe_original = tree.getroot()
                nfe_original = remover_ns_signature(nfe_original)
                nfe_original.attrib["xmlns"] = "http://www.portalfiscal.inf.br/nfe"

                procNFe.append(nfe_original)

                protNFe = ET.Element("protNFe", attrib={"versao": "4.00"})
                infProt = ET.SubElement(protNFe, "infProt")

                campos = {
                    "tpAmb": "1",
                    "verAplic": ret.get("verAplic"),
                    "chNFe": ret.get("chNFe"),
                    "dhRecbto": ret.get("dhRecbto"),
                    "nProt": ret.get("nProt"),
                    "digVal": ret.get("digVal"),
                    "cStat": ret.get("cStat"),
                    "xMotivo": ret.get("xMotivo")
                }

                for k, v in campos.items():
                    if v:
                        ET.SubElement(infProt, k).text = v

                procNFe.append(protNFe)
                ET.ElementTree(procNFe).write(saida, encoding="utf-8", xml_declaration=True)

                janela_validacao_xml.after(0, lambda: campo_query99.insert(
                    tk.END,
                    f"XML montado e salvo: {saida}\n",
                    'verde'
                ))

            except Exception as e:
                janela_validacao_xml.after(0, lambda e=e: campo_query99.insert(tk.END, f"Erro montagem: {e}\n",'vermelho'))

        # -----------------------------
        # 5. Rejeitado / não encontrado
        # -----------------------------
        elif codigo == "656":
            falhas_656 +=1
            red.add(chave_curta)
            shutil.copy2(arquivo_completo, indevidos)
            janela_validacao_xml.after(0, lambda: campo_query99.insert(
            tk.END,
            f"⚠️ CONSUMO INDEVIDO (656) -> Aguarde... | {chave_modificada}\n",
            'roxo'
            ))
            espera_segura(min (2 ** falhas_656, 120))
            continue

        else:
            falhas_consecutivas = 0
            falhas_656 = 0
            red.add(chave_curta)
            shutil.copy2(arquivo_completo, invalidos)
            janela_validacao_xml.after(0, lambda: campo_query99.insert(
                tk.END,
                f"❌ {codigo} -> {motivo} | {chave_modificada}\n",
                'vermelho'
            ))
        janela_validacao_xml.after(0, lambda: campo_query99.see(tk.END))
        # -----------------------------
        # 6. controle de taxa SEFAZ
        # -----------------------------
        janela_validacao_xml.after(0, lambda: campo_query99.insert(
            tk.END,"*" * 30 + "\n", 'branco'
        ))
    janela_validacao_xml.after(0, lambda: campo_query99.insert(
        tk.END,
        f"\nNÚMERAÇÕES VÁLIDADAS NA SEFAZ: {green}\n",
        'azul')) 
    janela_validacao_xml.after(0, lambda: campo_query99.insert(
        tk.END,
        f"\nNÚMERAÇÕES NÃO VÁLIDADAS NA SEFAZ: {red}\n",
        'vermelho'
    ))
        
    janela_validacao_xml.after(0, lambda: campo_query99.see(tk.END))
    janela_validacao_xml.after(0, lambda: botao_voltar.config(state='normal'))
    janela_validacao_xml.after(0, lambda: botao_validar_xml.config(state='normal'))


def buscar_xml_por_chave():
    arquivo_lista = "chave.txt"

    if os.path.exists(arquivo_lista) and os.path.exists(pasta_origem) and os.path.exists(xml_bruto):
        pasta_destino = f"{xml_bruto}"
        campo_query.config(state='normal') 
        campo_query.delete("1.0",tk.END)

        # Lê a lista de chaves (sem extensão, sem -nfe)
        chaves = []
        with open(arquivo_lista, "r", encoding="utf-8") as f:
          for linha in f:
              linha = linha.strip().lower()
              chaves.append(linha)  
        encontrados = set()
        # Percorre a pasta e subpastas
        for raiz, dirs, arquivos in os.walk(pasta_origem):
            for nome_arquivo in arquivos:
                nome_lower = nome_arquivo.lower()
                for chave in chaves:
                    chave_modificada = chave + '-nfe.xml'
                    if chave_modificada == nome_lower:
                        caminho_origem = os.path.join(raiz, nome_arquivo)
                        caminho_destino = os.path.join(pasta_destino, nome_arquivo)
                        shutil.copy2(caminho_origem, caminho_destino)
                        encontrados.add(chave)
                        campo_query.insert(tk.END, f"✅ Copiado: {nome_arquivo}\n")
                        break  # evita copiar o mesmo arquivo mais de uma vez

        # Mostra os que não foram encontrados
        nao_encontrados = [c for c in chaves if c not in encontrados]
        if nao_encontrados:
            campo_query.insert(tk.END,"\n⚠️ Arquivos não encontrados:\n")     
            with open("chaves_nao_encontradas.txt", "w") as arquivo:
                    for c in nao_encontrados:
                        arquivo.write(f"{c}\n")                
                        campo_query.insert(tk.END,f"{c}\n")
        else:
            campo_query.insert(tk.END,"\n🟢 Todos os arquivos foram encontrados e copiados!")

        campo_query.config(state='disabled')     
        campo_query.see(tk.END)
    else:
        messagebox.showerror(message='Verifique se a pasta "Docs" / "xml_bruto" ou o arquivo "chave.txt" existem na pasta onde está o executável.')
    

def buscar_xml_por_coo():
    chaves=[]
    arquivo_lista = "coo.txt"

    if os.path.exists(arquivo_lista) and os.path.exists(pasta_origem) and os.path.exists(xml_bruto):
        campo_query.config(state='normal') 
        campo_query.delete("1.0",tk.END)
        pasta_destino = f"{xml_bruto}"
        campo_query.delete("1.0",tk.END)
        with open(arquivo_lista, "r", encoding="utf-8") as f:
          for linha in f:
              linha = linha.strip().lower()
              chaves.append(linha)  
        encontrados = set()
        for raiz, dirs, arquivos in os.walk(pasta_origem):
            for nome_arquivo in arquivos:
                if nome_arquivo[-8:] == '-nfe.xml':
                    nome_lower = nome_arquivo.lower()
                    for chave in chaves:
                        if str(chave).lstrip("0") == nome_lower[25:34].lstrip("0"):
                            # Cria a pasta de destino se não existir
                            caminho_origem = os.path.join(raiz, nome_arquivo)
                            caminho_destino = os.path.join(pasta_destino, nome_arquivo)
                            shutil.copy2(caminho_origem, caminho_destino)
                            encontrados.add(chave)
                            campo_query.insert(tk.END, f"✅ Copiado: {nome_arquivo}\n")
                            break  # evita copiar o mesmo arquivo mais de uma vez
                        else:
                            pass
                else:
                    pass  
        # Mostra os que não foram encontrados
        nao_encontrados = [c for c in chaves if c not in encontrados]
        if nao_encontrados:
            campo_query.insert(tk.END,"\n⚠️ Arquivos não encontrados:\n")
            with open("coos_nao_encontrados.txt", "w") as arquivo:
                for c in nao_encontrados:
                    arquivo.write(f"{c}\n")     
                    campo_query.insert(tk.END,f"{c}\n")
        else:
            campo_query.insert(tk.END,"\n🟢 Todos os arquivos foram encontrados e copiados!")
            
        campo_query.config(state='disabled') 
        campo_query.see(tk.END)    
        
    else:
        messagebox.showerror(message='Verifique se a pasta "Docs" / "xml_bruto" ou o arquivo "coo.txt" existem na pasta onde está o executável.')


def selecionar_pasta(label):
    pasta = filedialog.askdirectory()
    if pasta:
        label.delete(0,tk.END)
        label.insert(0,pasta)


def selecionar_arquivo(label):
    pasta = filedialog.askopenfilename()
    if pasta:
        label.delete(0,tk.END)
        label.insert(0,pasta)


def validar_xml_thread(certificado,senha, xml_bruto, xml_saida):
    threading.Thread(target=validar_xml,args=(certificado,senha, xml_bruto,xml_saida)).start()


def voltar():
    janela_validacao_xml.withdraw()
    janela_principal.deiconify() 


def janela_validacao():
    global janela_validacao_xml,botao_validar_xml,botao_voltar,caminho_certificado,campo_query99,botao_caminho_certificado
    janela_principal.withdraw()
    janela_validacao_xml = tk.Toplevel()
    janela_validacao_xml.title("BDX 3.0 Desenvolvido por Gian")
    janela_validacao_xml.geometry("1000x800")
    janela_validacao_xml.protocol("WM_DELETE_WINDOW", voltar)
    frame_campos = tk.Frame(janela_validacao_xml,bg=COR_FUNDO)
    frame_campos.pack(pady=10)
    frame_botoes = tk.Frame(janela_validacao_xml,bg=COR_FUNDO)
    frame_botoes.pack(pady=10)
    janela_validacao_xml.configure(bg=COR_FUNDO)
    scroll = tk.Scrollbar(janela_validacao_xml)
    scroll.pack(side="right", fill="y")

    tk.Label(frame_campos, text="Caminho do certificado:",fg=COR_TEXTO,bg=COR_FUNDO).grid(row=1, column=0, padx=5)
    caminho_certificado = tk.Entry(frame_campos, width=60,bg=COR_TEXTO)
    caminho_certificado.grid(row=1, column=1, padx=5)
    botao_caminho_certificado = tk.Button(frame_campos, bg=COR_BOTAO,fg=COR_TEXTO, text="📁", command=lambda: selecionar_arquivo(caminho_certificado), padx=3, pady=3)
    botao_caminho_certificado.grid(row=1, column=2)

    tk.Label(frame_campos, text="Senha do certificado:",fg=COR_TEXTO,bg=COR_FUNDO).grid(row=2, column=0, padx=5)
    senha = tk.Entry(frame_campos, width=60, show='*')
    senha.grid(row=2, column=1, padx=5)

    botao_validar_xml = tk.Button(frame_botoes,bg=COR_BOTAO,fg=COR_TEXTO, text="Iniciar", command=lambda: validar_xml_thread(caminho_certificado.get(),senha.get(),xml_bruto,xml_lapidado), padx=10, pady=10)
    botao_validar_xml.grid(row=0, column=0,padx=10)

    botao_voltar = tk.Button(frame_botoes,bg=COR_BOTAO,fg=COR_TEXTO, text="Voltar", command= voltar, padx=10, pady=10)
    botao_voltar.grid(row=0,column=1,padx=10)
    

    campo_query99 = tk.Text(janela_validacao_xml, width=130, height=100,bg=COR_FRAME,yscrollcommand=scroll.set)
    campo_query99.pack(pady=5,side='bottom',fill="both",expand=True)
    scroll.config(command=campo_query99.yview)
    campo_query99.tag_config("verde", foreground="green")
    campo_query99.tag_config("vermelho", foreground="red")
    campo_query99.tag_config("azul", foreground="blue")
    campo_query99.tag_config("amarelo", foreground="yellow")
    campo_query99.tag_config("branco", foreground=COR_TEXTO)
    campo_query99.tag_config("rosa", foreground="pink")
    campo_query99.tag_config("roxo", foreground="purple")


global campo_query, janela_principal
janela_principal = tk.Tk()
janela_principal.protocol("WM_DELETE_WINDOW", fechar)
janela_principal.title("BDX 3.0 Desenvolvido por Gian")  # Título da janela
janela_principal.geometry("600x600")  # Largura x Altura
janela_principal.configure(bg=COR_FUNDO)
frame_botoes = tk.Frame(janela_principal, bg=COR_FUNDO)
frame_botoes.pack(pady=10)
botao = tk.Button(frame_botoes, text="Buscar xml por chave",
                  command=buscar_xml_por_chave,
                  padx=20, pady=20, fg=COR_TEXTO, bg=COR_BOTAO)
botao.pack(side="left", padx=5)

botao2 = tk.Button(frame_botoes, text="Buscar xml por coo",
                   command=buscar_xml_por_coo,
                   padx=20, pady=20, fg=COR_TEXTO, bg=COR_BOTAO)
botao2.pack(side="left", padx=5)

botao4 = tk.Button(frame_botoes, text="Validar xml",
                   command=janela_validacao,
                   padx=20, pady=20, fg=COR_TEXTO, bg=COR_BOTAO)
botao4.pack(side="left", padx=5)

campo_query = tk.Text(janela_principal, width=120, height=100,bg=COR_FRAME,fg="white",state='disabled')
campo_query.pack(pady=5)
janela_principal.mainloop()
