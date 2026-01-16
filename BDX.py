import os
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import messagebox
import requests
import xml.etree.ElementTree as ET
import threading
import time
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from tkinter import filedialog

COR_FUNDO = "#1e1e2e"
COR_FRAME = "#2a2a3d"
COR_TEXTO = "#eaeaf0"   
COR_BOTAO = "#3b82f6" 

data_atual = datetime.now()
nome_pasta = data_atual.strftime("%Y-%m-%d_%H%M")
pasta_origem = 'docs'
pasta_autorizados = 'xmls_autorizados'
pasta_invalidas = 'xmls_nao_autorizados'
log_tecnico = 'log'


try:
    with open('log.txt','a') as z:
        z.write('\n\n\n\n\n')
        z.write('*************************\n')
        z.write(f' NOVO LOG {data_atual}\n')
        z.write('*************************\n')
        z.write('\n\n\n\n\n')

except FileExistsError:
    pass

except Exception as erro:
    messagebox.showerror(message=f'{erro}')


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
        janela2.after(0,lambda e=erro: messagebox.showerror(f"Erro de certificado",{str(e)}))
        return None,None


def limpar(xml):
    """Remove quebras de linha e BOM do XML."""
    return "".join(l.strip() for l in xml.lstrip("\ufeff").splitlines() if l.strip())


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
        "infProt": infProt is not None
    }



def janela():
    global campo_query, janela_principal
    janela_principal = tk.Tk()
    janela_principal.title("BDX 2.2")  # Título da janela
    janela_principal.geometry("600x600")  # Largura x Altura
    janela_principal.configure(bg=COR_FUNDO)
    
    botao = tk.Button(janela_principal, text="Buscar xml por chave", command=buscar_xml_por_chave, padx=20, pady=20,fg=COR_TEXTO,bg=COR_BOTAO)
    botao.pack(pady=10)
    botao2 = tk.Button(janela_principal, text="Buscar xml por coo", command=buscar_xml_por_coo, padx=20, pady=20,fg=COR_TEXTO,bg=COR_BOTAO)
    botao2.pack(pady=10)
    botao3 = tk.Button(janela_principal, text="Validação de xml", command=janela_nova, padx=20, pady=20,fg=COR_TEXTO,bg=COR_BOTAO)
    botao3.pack(pady=10)

    campo_query = tk.Text(janela_principal, width=120, height=100,bg=COR_FRAME,fg="white",state='disabled')
    campo_query.pack(pady=5)
    janela_principal.mainloop()


def buscar_xml_por_chave():
    arquivo_lista = "chave.txt"

    if os.path.exists(arquivo_lista) and os.path.exists(pasta_origem):
        pasta_destino = f"{nome_pasta}_BDX_CHAVE"
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
                        os.makedirs(pasta_destino, exist_ok=True)
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
        messagebox.showerror(message='Verifique se a pasta ‘Docs’ ou o arquivo ‘chave.txt’ existem na pasta onde está o executável.')
    

def buscar_xml_por_coo():
    chaves=[]
    arquivo_lista = "coo.txt"

    if os.path.exists(arquivo_lista) and os.path.exists(pasta_origem):
        campo_query.config(state='normal') 
        campo_query.delete("1.0",tk.END)
        pasta_destino = f"{nome_pasta}_BDX_COO"
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
                            os.makedirs(pasta_destino, exist_ok=True)
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
        messagebox.showerror(message='Verifique se a pasta ‘Docs’ ou o arquivo coo.txt’ existem na pasta onde está o executável.')


def validar_xml(pasta,certificado,senha):
    if not os.path.exists(pasta):
        janela2.after(0,lambda: messagebox.showerror("Erro", "Caminho do xml não encontrado!"))  
        return     

    elif not os.path.exists(certificado):
        janela2.after(0,lambda: messagebox.showerror("Erro", "Caminho do certificado não encontrado!"))  
        return

    else:
        green = set()
        red = set()
        green1 = set()
        red1 = set()
        certificado = str(certificado).strip()
        senha = str(senha).strip()
        CERT_FILE, KEY_FILE = load_pfx(certificado, senha)

        if CERT_FILE is None or KEY_FILE is None:
            return
    botao_voltar.config(state="disabled")
    botao_validar_xml.config(state="disabled")
    campo_query1.config(state="normal")
    qtd_itens = 0
    qtd_itens_validos = 0         
    for raiz, dirs, arquivos in os.walk(pasta):
            for nome_arquivo in arquivos:
                if nome_arquivo.endswith('-nfe.xml'):
                    arquivo_xml = os.path.join(raiz, nome_arquivo)
                    qtd_itens+=1
                    chave = nome_arquivo[25:34].lstrip("0")
                    if chave in green:
                        campo_query1.after(0, lambda: campo_query1.insert(tk.END,f"\n"))
                        campo_query1.after(0, lambda: campo_query1.insert(tk.END,f"***CHAVE JÁ VALIDADA***: {nome_arquivo}",'amarelo'))
                        campo_query1.after(0, lambda: campo_query1.insert(tk.END,f"\n"))
                        try:
                            with open('log.txt', 'a', encoding='utf-8') as g:
                                g.write('*************************\n')
                                g.write(f'COO {chave}\n')
                                g.write(f'CHAVE {chave}\n')
                                g.write('Info: Chave já autorizada!\n')
                                g.write('*************************\n')

                        except Exception as erro:
                                    messagebox.showerror(message=f'{erro}')

                        red.discard(chave)
                        red1.discard(nome_arquivo)
                        continue
                    else:
                        os.makedirs(pasta_autorizados, exist_ok=True)
                        os.makedirs(pasta_invalidas, exist_ok=True)
                        chave_modificada = nome_arquivo.removesuffix('-nfe.xml')
                        xml_nfe = limpar(xml_consulta(chave_modificada))
                        soap_xml = montar_soap(xml_nfe)
                        url = "https://nfce.fazenda.sp.gov.br/ws/NFeConsultaProtocolo4.asmx"
                        headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
                        try:
                            response = requests.post(url, data=soap_xml.encode("utf-8"), headers=headers, cert=(CERT_FILE, KEY_FILE), verify=False, timeout=(5,15))

                        except Exception as erro:
                            campo_query1.after(0, lambda e=erro: campo_query1.insert(tk.END, f"NÚMERO DA CHAVE: {chave} {str(e)}" + "\n",'branco'))

                        else:
                            ret = extrair_prot(response.text) 
                            if not ret:
                                 campo_query1.after(0, lambda: campo_query1.insert(tk.END, "⚠️ Resposta inválida da SEFAZ\n", 'vermelho'))
                                 continue
                            codigo = ret.get("cStat")   
                            motivo = ret.get("xMotivo")      
                            try:
                                with open('log.txt', 'a', encoding='utf-8') as g:
                                        g.write('*************************\n')
                                        g.write(f'COO {chave}\n')
                                        g.write(f'CHAVE {chave}\n')
                                        g.write(f'{codigo} : {motivo}\n')
                                        g.write('*************************\n')

                            except Exception as erro:
                                    messagebox.showerror(message=f'{erro}')      

                            campo_query1.after(0, lambda: campo_query1.insert(tk.END, "\n" + "*"*30 + "\n",'branco'))
                            if ret and ret.get("cStat") == "100":
                                qtd_itens_validos +=1
                                # XML encontrado via SEFAZ
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END,'🟢 XML AUTORIZADO! 🟢⚠️\n','verde'))
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END,f"COO: {chave}\n",'verde'))
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END,f"CHAVE: {nome_arquivo}\n",'verde'))
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END, f"Info:{codigo} -> {motivo}\n",'verde'))
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END, f"Protocolo: {ret.get('nProt')}\n",'verde'))
                                campo_query1.see(tk.END)
                                green.add(chave)
                                red.discard(chave)
                                red1.discard(nome_arquivo)
                                green1.add(nome_arquivo)
                                caminho_origem = os.path.join(pasta_origem, nome_arquivo)
                                caminho_destino = os.path.join(pasta_autorizados, nome_arquivo)
                                shutil.copy2(caminho_origem, caminho_destino)
                               
                            else:  
                                if chave not in green:
                                    red.add(chave)
                                if chave not in green1:
                                    red1.add(nome_arquivo)    
                                arquivo_xml = os.path.join(raiz, nome_arquivo)
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END, f"Info: {codigo} -> {motivo}\n",'vermelho'))
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END, f"COO: {chave}\n",'vermelho'))
                                campo_query1.after(0, lambda: campo_query1.insert(tk.END, f"CHAVE: {nome_arquivo}\n",'vermelho'))

                                caminho_origem = os.path.join(pasta_origem, nome_arquivo)
                                caminho_destino = os.path.join(pasta_invalidas, nome_arquivo)
                                shutil.copy2(caminho_origem, caminho_destino)
                                
                    campo_query1.see(tk.END)    
                    time.sleep(2)

    campo_query1.after(0, lambda: campo_query1.insert(tk.END, "\n" + "*"*30 + "\n",'branco'))  
    campo_query1.after(0, lambda: campo_query1.insert(tk.END, f'QUANTIDADE DE XML ANALISADOS: {qtd_itens}'+"\n",'branco'))    
    campo_query1.after(0, lambda: campo_query1.insert(tk.END, f'QUANTIDADE DE XML AUTORIZADOS NA SEFAZ: {qtd_itens_validos}'+"\n",'branco'))    
    campo_query1.after(0, lambda: campo_query1.insert(tk.END, f'QUANTIDADE DE XML NÃO AUTORIZADOS NA SEFAZ: {qtd_itens - qtd_itens_validos}'+"\n",'branco')) 
    campo_query1.after(0, lambda: campo_query1.insert(tk.END, f'LISTA DOS AUTORIZADOS: {green}\n'))
    campo_query1.after(0, lambda: campo_query1.insert(tk.END, f'LISTA DOS NÃO AUTORIZADOS: {red}\n'))
    campo_query1.see(tk.END) 
    botao_validar_xml.config(state="normal")
    botao_voltar.config(state="normal")
    campo_query1.config(state="disabled")
    retorno = []
    retorno2 = []
    try:
        with open("coos_nao_encontrados.txt", "w", encoding="utf-8") as arquivo:
            for x in red:
                arquivo.write(f"{x}\n")

        arquivo_lista = "coos_nao_encontrados.txt"  # corrigido: com extensão
        with open(arquivo_lista, "r", encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip().lower()
                retorno.append(linha)

        retorno.sort()
        with open("coos_nao_encontrados.txt", "w", encoding="utf-8") as arquivo:
            for x in retorno:
                arquivo.write(f"{x}\n")

    except:
        campo_query1.after(0, lambda: campo_query1.insert(tk.END, 'Falha na leitura de coos_nao_encontrados.txt!'))


    try:
        with open("chaves_nao_encontradas.txt", "w", encoding="utf-8") as arquivo:
            for x in red1:
                arquivo.write(f"{x}\n")

        arquivo_lista = "chaves_nao_encontradas.txt"  # corrigido: com extensão
        with open(arquivo_lista, "r", encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip().lower()
                retorno2.append(linha)


        with open("chaves_nao_encontradas.txt", "w", encoding="utf-8") as arquivo:
            for x in retorno2:
                arquivo.write(f"{x}\n")

    except:
        campo_query1.after(0, lambda: campo_query1.insert(tk.END, 'Falha na leitura de chaves_nao_encontradas.txt!'))    


def janela_nova():
    global janela2, campo_query1,botao_validar_xml,botao_voltar,caminho_certificado
    janela_principal.withdraw()
    janela2 = tk.Toplevel()
    janela2.title("BDX 2.2")
    janela2.geometry("1000x800")
    frame_campos = tk.Frame(janela2,bg=COR_FUNDO)
    frame_campos.pack(pady=10)
    frame_botoes = tk.Frame(janela2,bg=COR_FUNDO)
    frame_botoes.pack(pady=10)
    janela2.configure(bg=COR_FUNDO)
    scroll = tk.Scrollbar(janela2)
    scroll.pack(side="right", fill="y")
    
    tk.Label(frame_campos, text="Caminho do XML:",fg=COR_TEXTO,width=20, anchor="e",bg=COR_FUNDO).grid(row=0,column=0,padx=5)
    caminho_xml = tk.Entry(frame_campos, width=60,bg=COR_TEXTO)
    caminho_xml.grid(row=0, column=1, padx=5)
    botao_caminho_xml = tk.Button(frame_campos, bg=COR_BOTAO,fg=COR_TEXTO, text="📁", command=lambda: selecionar_pasta(caminho_xml), padx=3, pady=3)
    botao_caminho_xml.grid(row=0, column=2)

    tk.Label(frame_campos, text="Caminho do certificado:",fg=COR_TEXTO,bg=COR_FUNDO).grid(row=1, column=0, padx=5)
    caminho_certificado = tk.Entry(frame_campos, width=60,bg=COR_TEXTO)
    caminho_certificado.grid(row=1, column=1, padx=5)
    botao_caminho_certificado = tk.Button(frame_campos, bg=COR_BOTAO,fg=COR_TEXTO, text="📁", command=lambda: selecionar_arquivo(caminho_certificado), padx=3, pady=3)
    botao_caminho_certificado.grid(row=1, column=2)

    tk.Label(frame_campos, text="Senha do certificado:",fg=COR_TEXTO,bg=COR_FUNDO).grid(row=2, column=0, padx=5)
    senha = tk.Entry(frame_campos, width=60, show='*')
    senha.grid(row=2, column=1, padx=5)

    botao_validar_xml = tk.Button(frame_botoes,bg=COR_BOTAO,fg=COR_TEXTO, text="Validar xml", command=lambda: validar_xml_thread(caminho_xml.get(),caminho_certificado.get(),senha.get()), padx=10, pady=10)
    botao_validar_xml.grid(row=0, column=0,padx=10)

    botao_voltar = tk.Button(frame_botoes,bg=COR_BOTAO,fg=COR_TEXTO, text="Voltar", command= voltar, padx=10, pady=10)
    botao_voltar.grid(row=0,column=1,padx=10)
    

    campo_query1 = tk.Text(janela2, width=130, height=100,bg=COR_FRAME,yscrollcommand=scroll.set)
    campo_query1.pack(pady=5,side='bottom',fill="both",expand=True)
    scroll.config(command=campo_query1.yview)
    campo_query1.tag_config("verde", foreground="green")
    campo_query1.tag_config("vermelho", foreground="red")
    campo_query1.tag_config("azul", foreground="blue")
    campo_query1.tag_config("amarelo", foreground="yellow")
    campo_query1.tag_config("branco", foreground=COR_TEXTO)
    campo_query1.config(state="disabled")

   
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


def validar_xml_thread(pasta,certificado,senha):
    threading.Thread(target=validar_xml,args=(pasta,certificado,senha)).start()


def voltar():
    janela2.withdraw()
    janela_principal.deiconify()


janela()
