from iputils import *
import struct
import ipaddress

class CamadaRede:
    def __init__(self, meio_enlace):
        self.receptor = None
        self.enlace = meio_enlace
        self.enlace.registrar_recebedor(self._receptor_cru)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.endereco_local = None
        self.rotas = None

    def tratar_tempo_excedido(self, origem, pacote):
        proximo = self._resolver_proximo(origem)

        tamanho_total = 48
        ttl_padrao = 64
        protocolo = IPPROTO_ICMP

        cabecalho = self._gerar_cabecalho(tamanho_total, ttl_padrao, protocolo, self.endereco_local, origem)

        tipo = 11
        codigo = 0
        icmp_hdr = struct.pack('!BBHHH', tipo, codigo, 0, 0, 0)

        restante = pacote[:28]
        verificador = calc_checksum(icmp_hdr + restante)

        icmp_hdr = struct.pack('!BBHHH', tipo, codigo, verificador, 0, 0)
        self.enlace.enviar(cabecalho + icmp_hdr + restante, proximo)

    def _gerar_cabecalho(self, tamanho, ttl, protocolo, origem, destino, verificador=0):
        origem = int(ipaddress.IPv4Address(origem))
        destino = int(ipaddress.IPv4Address(destino))

        cab = struct.pack(
            '!BBHHHBBHII',
            (4 << 4) + 5, 0, tamanho, 0, 0,
            ttl, protocolo, verificador, origem, destino
        )

        if verificador == 0:
            verificador = calc_checksum(cab)
            cab = struct.pack(
                '!BBHHHBBHII',
                (4 << 4) + 5, 0, tamanho, 0, 0,
                ttl, protocolo, verificador, origem, destino
            )

        return cab

    def _receptor_cru(self, datagrama):
        dscp, ecn, identificador, flags, deslocamento, ttl, proto, origem, destino, conteudo = read_ipv4_header(datagrama)

        if destino == self.endereco_local:
            if proto == IPPROTO_TCP and self.receptor:
                self.receptor(origem, destino, conteudo)
        else:
            proximo = self._resolver_proximo(destino)
            ttl -= 1

            if ttl == 0:
                self.tratar_tempo_excedido(origem, datagrama)
                return

            novo_cab = self._gerar_cabecalho(20 + len(datagrama), ttl, proto, origem, destino)
            novo_pacote = novo_cab + conteudo
            self.enlace.enviar(novo_pacote, proximo)

    def _resolver_proximo(self, destino):
        ip_dest = ipaddress.ip_address(destino)
        alternativas = [
            (ipaddress.ip_network(rede).prefixlen, via)
            for rede, via in self.rotas
            if ip_dest in ipaddress.ip_network(rede)
        ]
        return max(alternativas, key=lambda x: x[0])[1] if alternativas else None

    def configurar_endereco(self, local):
        self.endereco_local = local

    def configurar_tabela_rotas(self, rotas):
        self.rotas = rotas

    def registrar_receptor(self, receptor):
        self.receptor = receptor

    def transmitir(self, conteudo, destino):
        proximo = self._resolver_proximo(destino)
        tamanho = 20 + len(conteudo)
        cab = self._gerar_cabecalho(tamanho, 64, 6, self.endereco_local, destino)
        pacote = cab + conteudo
        self.enlace.enviar(pacote, proximo)
