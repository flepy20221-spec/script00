#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 glory_gold.py — SOMENTE a lógica de GOLD do Glory Tiger Party
================================================================================
 Fluxo replicado 1:1 da captura real (13 sessões, 22/09 15:57) + engenharia
 reversa (classes3.dex). Toda a camada de ad networks (AppLovin ms4/mediate,
 prod-mediate-events, d.applovin.com/mcr, Mintegral mtgglobals) NÃO é chamada
 aqui — ela acontece dentro dos SDKs no app. O que este script replica é
 EXATAMENTE o que o app envia/recebe no backend próprio:

   • Host do jogo: app.claudioalloccanotqua.top (HTTP puro, porta 80)
   • Headers fixos: appName: glorytigerparty | vpn: 1 | okhttp/4.10.0
   • Criptografia: XXTEA little-endian, chave "glorytigerpartyf"
     (literal no DEX: "glorytigerpartyfgh" truncada p/ 16 bytes), sem IV,
     tamanho original anexado ao último uint32.
     Fluxo: Gson JSON -> nGxxoe.OeGllo() (XXTEA) -> Base64 -> OkHttp POST
     Resposta: Base64 -> nGxxoe.dOGGOGd() (XXTEA^-1) -> JSON
     Vetor: {"cla_ud":"test"} -> WHDQVhAlMFdH3R1e1ExBeCPScwBrtk12  ✅

 ── ORDEM REAL OBSERVADA NA CAPTURA (sorted por timestamp) ──────────────────
   15:57:45  POST /app/.../htw68e5f1ozuysihvu   emite cla_bd (batch id)
             req:  {"cla_ud":"...","cla_tp":1,"cla_nt":1790103464,
                    "cla_bcd":"1f2ee945db7c1f67"}
             resp: {"cla_bd":"4107726c...","cla_st":"0"}
   15:57:45  POST /ads/.../lu4vf36b26f2q03rn9   evento gg_clse (ad fechado)
             req:  {...,"cla_em":"12.552415","cla_bd":"",...}
   15:57:46  POST /ads/.../lu4vf36b26f2q03rn9   evento gg_lad (ad carregado)
             req:  {...,"cla_em":"13.28513516","cla_bd":"4107726c...",...}
   (em paralelo, fora deste script: AppLovin mediate/mcls/mcr + reward Mintegral)

 Rotas do GOLD (somente gold — lógica de saque REMOVIDA):
   /app/glorytigerparty/Claudioalloccanotqua/
     vb0i835j55xfteiips  carteira/saldo: cla_bl (gold), cla_rbl (R$)
     htw68e5f1ozuysihvu  emite cla_bd (batch id) — pré-condição do crédito
     mcfvsx9mxgbineefbh  ★ CRÉDITO do gold após rewarded ad (captura anterior)
     pld291sjstwpaxklew  stats da sessão (cla_ads, cla_rs, cla_ts)
   /ads/glorytigerparty/Claudioalloccanotqua/
     lu4vf36b26f2q03rn9  eventos de ad p/ backend próprio (gg_clse / gg_lad)

 MODO TESTE vs REAL:
   MODE=test  (padrão)  -> só loga os payloads, NÃO chama o servidor
   MODE=real            -> executa as chamadas ao vivo no backend
   (DRY_RUN continua aceito p/ compatibilidade: DRY_RUN=0 equivale a MODE=real)

 USO:
   pip install requests
   python glory_gold.py                                 # TESTE (só loga)
   MODE=real CLA_UD=<seu_uid> python glory_gold.py      # fluxo ao vivo
================================================================================
"""

from __future__ import annotations

import base64
import json
import logging
import os
import struct
import time
import uuid
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
# MODE=test (padrão, só loga) | MODE=real (chama o servidor de verdade)
MODE = os.environ.get("MODE", "test").strip().lower()
if "DRY_RUN" in os.environ:  # compatibilidade com a variável antiga
    MODE = "real" if os.environ["DRY_RUN"] in ("0", "false", "False") else "test"
DRY_RUN = MODE != "real"
TIMEOUT = 15
# uid observado nesta captura (era o cuid do AppLovin também)
CLA_UD = os.environ.get("CLA_UD", "8fcc591a56b24033acdd914b624d0fb5")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("glory-gold")

APP_VER = "1.0.1"      # cla_vn
APP_VC = 101           # vn
GAID = "f88633c7-bd3e-48e7-a22e-25ba3f7d6ad3"

# Constantes do bloco de ads vistas na captura
AD_UNIT_ID = "1f2ee945db7c1f67"   # AppLovin-Ad-Unit-Id / cla_cid / cla_bcd
MINTEGRAL_PLACEMENT = "6408107"   # cla_mpf (AppLovin-Third-Party-Ad-Placement-Id)
AD_PLATFORM = "Max"               # cla_pf  (mediação AppLovin MAX)
AD_NETWORK = "Mintegral"          # cla_mcd (vencedor do leilão na captura)
AD_TYPE = "gg_rew"                # cla_tp  (rewarded)
AD_CA = 2                         # cla_ca
AD_NT = "Organic"                 # cla_nt

# ============================================================================
# XXTEA — confirmado via RE (classes3.dex: nGxxoe)
# ============================================================================
_DELTA = 0x9E3779B9
_MASK = 0xFFFFFFFF
XXTEA_KEY_STR = "glorytigerpartyf"
_K = list(struct.unpack("<4I", XXTEA_KEY_STR.encode()))


def _mx(z, y, s, p, e, k):
    return ((((z >> 5) ^ ((y << 2) & _MASK)) + ((y >> 3) ^ ((z << 4) & _MASK))) & _MASK
            ^ (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & _MASK)) & _MASK


def _enc_uints(v, k):
    n = len(v)
    if n < 2:
        return v
    rounds = 6 + 52 // n
    s, z = 0, v[n - 1]
    for _ in range(rounds):
        s = (s + _DELTA) & _MASK
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + _mx(z, y, s, p, e, k)) & _MASK
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + _mx(z, y, s, n - 1, e, k)) & _MASK
        z = v[n - 1]
    return v


def _dec_uints(v, k):
    n = len(v)
    if n < 2:
        return v
    rounds = 6 + 52 // n
    s = (rounds * _DELTA) & _MASK
    y = v[0]
    while s:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(z, y, s, p, e, k)) & _MASK
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _mx(z, y, s, 0, e, k)) & _MASK
        y = v[0]
        s = (s - _DELTA) & _MASK
    return v


def xxtea_encrypt_text(text: str) -> str:
    """JSON UTF-8 -> XXTEA -> Base64  ==  nGxxoe.OeGllo()"""
    data = text.encode("utf-8")
    orig_len = len(data)
    if len(data) % 4:
        data += b"\x00" * (4 - len(data) % 4)
    v = list(struct.unpack("<%dI" % (len(data) // 4), data))
    v.append(orig_len)
    enc = _enc_uints(v, _K)
    return base64.b64encode(struct.pack("<%dI" % len(enc), *enc)).decode()


def xxtea_decrypt_b64(b64: str) -> str:
    """Base64 -> XXTEA^-1 -> JSON UTF-8  ==  nGxxoe.dOGGOGd()"""
    blob = base64.b64decode(b64.strip())
    v = list(struct.unpack("<%dI" % (len(blob) // 4), blob))
    dec = _dec_uints(v, _K)
    length = dec[-1]
    raw = struct.pack("<%dI" % (len(dec) - 1), *dec[:-1])[:length]
    return raw.decode("utf-8", errors="replace")


# auto-teste no import — falha ruidosamente se a chave estiver errada
assert xxtea_encrypt_text('{"cla_ud":"test"}') == "WHDQVhAlMFdH3R1e1ExBeCPScwBrtk12", \
    "XXTEA fora do vetor de validação!"

# vetores reais desta captura (garantem que o payload bate byte a byte)
assert xxtea_decrypt_b64(xxtea_encrypt_text(
    '{"cla_ud":"8fcc591a56b24033acdd914b624d0fb5"}'
)).startswith('{"cla_ud"')


def new_uuid() -> str:
    return str(uuid.uuid4())


def now_s() -> int:
    return int(time.time())


# ============================================================================
# API do jogo — envelope idêntico ao app (headers + XXTEA + okhttp)
# ============================================================================
class GoldApi:
    BASE = "http://app.claudioalloccanotqua.top"
    NS_APP = "app/glorytigerparty/Claudioalloccanotqua"
    NS_ADS = "ads/glorytigerparty/Claudioalloccanotqua"   # <- namespace /ads/ da captura

    def __init__(self, cla_ud: str = CLA_UD):
        self.cla_ud = cla_ud
        self.log = logging.getLogger("glory-gold.api")
        self.s = requests.Session()
        retry = Retry(total=3, backoff_factor=0.6,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset(["GET", "POST"]))
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        # headers fixos observados na captura (ordem/valores idênticos)
        self.s.headers.update({
            "appName": "glorytigerparty",
            "vpn": "1",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "okhttp/4.10.0",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
        })

    def _call(self, route: str, payload: Dict[str, Any],
              namespace: str = None) -> Optional[dict]:
        """Cifra (XXTEA->B64), POSTa, decifra a resposta e retorna dict."""
        ns = namespace or self.NS_APP
        url = f"{self.BASE}/{ns}/{route}"
        plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        body = xxtea_encrypt_text(plain)
        self.log.info("POST %s", url)
        self.log.info("  -> plain: %s", plain[:300])
        if DRY_RUN:
            self.log.info("  -> b64: %s...", body[:64])
            return None
        try:
            r = self.s.post(url, data=body, timeout=TIMEOUT)
            self.log.info("  <- HTTP %s (%d bytes)", r.status_code, len(r.content))
            resp_plain = xxtea_decrypt_b64(r.text)
            self.log.info("  <- decifrado: %s", resp_plain[:500])
            return json.loads(resp_plain)
        except (requests.RequestException, ValueError) as e:
            self.log.warning("  !! falha: %s", e)
            return None

    # ------------------------------------------------------------------
    # /app/ — rotas do GOLD (payloads EXATOS desta captura)
    # ------------------------------------------------------------------
    def wallet(self) -> Optional[dict]:
        """vb0i835j55xfteiips — saldo: cla_bl (gold), cla_rbl (R$), níveis."""
        return self._call("vb0i835j55xfteiips",
                          {"cla_ud": self.cla_ud, "vn": APP_VC})

    def get_batch_id(self) -> Optional[str]:
        """
        htw68e5f1ozuysihvu — emite cla_bd (batch id).

        PAYLOAD REAL DA CAPTURA (15:57:45):
          {"cla_ud":"...","cla_tp":1,"cla_nt":1790103464,"cla_bcd":"1f2ee945db7c1f67"}
        resp: {"code":0,"data":{"cla_bd":"4107726c...","cla_st":"0"}}
        """
        resp = self._call("htw68e5f1ozuysihvu", {
            "cla_ud": self.cla_ud,
            "cla_tp": 1,
            "cla_nt": now_s(),          # epoch seconds (1790103464 na captura)
            "cla_bcd": AD_UNIT_ID,      # ad unit que vai exibir o rewarded
        })
        if resp:
            return resp.get("data", {}).get("cla_bd")
        return None

    def credit_gold(self, cla_bd: str, cla_em: str, cla_bad: str,
                    cla_jsc: float, cla_ppp: str = "BIGO Ads",
                    cla_add: str = AD_UNIT_ID) -> Optional[dict]:
        """
        mcfvsx9mxgbineefbh — ★ rota de CRÉDITO do gold (captura anterior).

        ATENÇÃO: o servidor cruza cla_bd, cla_bad (bid id) e cla_em (eCPM)
        com callbacks server-to-server das ad networks. Ids reciclados/
        inventados = rejeitado + risco de flag de fraude. Use apenas com
        ids de um ad REAL.
        """
        payload = {
            "cla_vn": APP_VER,
            "cla_em": cla_em,
            "cla_ppp": cla_ppp,
            "cla_t": 2,
            "cla_ud": self.cla_ud,
            "cla_bad": cla_bad,
            "cla_jsc": cla_jsc,
            "cla_gid": GAID,
            "cla_tp": 1,
            "cla_add": cla_add,
            "cla_bd": cla_bd,
        }
        return self._call("mcfvsx9mxgbineefbh", payload)

    def session_stats(self) -> Optional[dict]:
        """pld291sjstwpaxklew — stats: cla_ads, cla_rs, cla_ts."""
        return self._call("pld291sjstwpaxklew",
                          {"cla_ud": self.cla_ud, "cla_tp": "2", "vn": APP_VC})

    # ------------------------------------------------------------------
    # /ads/ — telemetria de ad p/ o backend próprio (NOVO nesta captura)
    # ------------------------------------------------------------------
    def ad_event(self, evc: str, cla_em: str, cla_bd: str = "",
                 cla_rt: int = None, cla_mcd: str = AD_NETWORK) -> Optional[dict]:
        """
        lu4vf36b26f2q03rn9 (namespace /ads/) — o app reporta ao PRÓPRIO
        backend os eventos do rewarded ad. Dois eventos na captura:

          gg_clse (15:57:45): ad fechado   -> cla_bd=""      cla_em="12.552415"
          gg_lad  (15:57:46): ad carregado -> cla_bd="4107.." cla_em="13.28513516"

        PAYLOAD REAL DA CAPTURA:
          {"cla_cid":"1f2ee945db7c1f67","cla_em":"13.28513516",
           "cla_aid":"glorytigerparty","cla_nt":"Organic","cla_ag":"",
           "cla_mpf":"6408107","cla_rt":1790103466,
           "cla_bd":"4107726c4c3541e2a013908c715e8a56","cla_cmp":"",
           "cla_ca":2,"cla_tp":"gg_rew","cla_vn":"1.0.1","cla_pf":"Max",
           "cla_cr":"","cla_ud":"...","cla_evc":"gg_lad","cla_mcd":"Mintegral"}
        resp: {"code":0,"errmsg":"success","data":true}
        """
        payload = {
            "cla_cid": AD_UNIT_ID,            # ad unit id
            "cla_em": cla_em,                 # eCPM do lance vencedor
            "cla_aid": "glorytigerparty",
            "cla_nt": AD_NT,                  # "Organic"
            "cla_ag": "",
            "cla_mpf": MINTEGRAL_PLACEMENT,   # placement da rede vencedora
            "cla_rt": cla_rt or now_s(),      # epoch do evento
            "cla_bd": cla_bd,                 # batch id (vazio no gg_clse)
            "cla_cmp": "",
            "cla_ca": AD_CA,                  # 2
            "cla_tp": AD_TYPE,                # "gg_rew"
            "cla_vn": APP_VER,                # "1.0.1"
            "cla_pf": AD_PLATFORM,            # "Max"
            "cla_cr": "",
            "cla_ud": self.cla_ud,
            "cla_evc": evc,                   # "gg_clse" | "gg_lad"
            "cla_mcd": cla_mcd,               # rede vencedora ("Mintegral")
        }
        return self._call("lu4vf36b26f2q03rn9", payload, namespace=self.NS_ADS)

    def ad_closed(self, cla_em: str) -> Optional[dict]:
        """gg_clse — reward concedido / ad fechado (cla_bd ainda vazio)."""
        return self.ad_event("gg_clse", cla_em, cla_bd="")

    def ad_loaded(self, cla_em: str, cla_bd: str) -> Optional[dict]:
        """gg_lad — próximo ad carregado, já vinculado ao cla_bd da sessão."""
        return self.ad_event("gg_lad", cla_em, cla_bd=cla_bd)


# ============================================================================
# Fluxo do gold — MESMA sequência da captura (somente camada do jogo)
# ============================================================================
class GoldFlow:
    """
    Sequência do GOLD observada na captura (timestamps reais), somente
    backend do jogo (lógica de saque removida):

      1. get_batch_id()                # 15:57:45 -> cla_bd
      2. ad_closed(em="12.552415")     # 15:57:45 gg_clse (reward do ad anterior)
      3. ad_loaded(em="13.28513516",   # 15:57:46 gg_lad  (próximo ad + cla_bd)
                   cla_bd=...)

    As chamadas AppLovin (ms4/mediate, mcls, mcr) e o reward callback da
    Mintegral NÃO estão aqui: são feitas pelos SDKs dentro do app e não
    falam com o backend do jogo.
    """

    def __init__(self, cla_ud: str = CLA_UD):
        self.api = GoldApi(cla_ud)
        self.log = logging.getLogger("glory-gold.flow")

    def consultar_saldo(self) -> Optional[dict]:
        """Read-only: saldo + níveis de conversão. Seguro ao vivo."""
        self.log.info("🪙 Consultando saldo...")
        return self.api.wallet()

    def fluxo_captura(self, em_clse: str = "12.552415",
                      em_lad: str = "13.28513516") -> Dict[str, Any]:
        """
        Replica o MESMO fluxo da captura. Os eCPMs default são os valores
        reais observados; em uso ao vivo, passe os eCPMs do leilão atual.
        """
        self.log.info("🪙 [1/3] batch id da sessão...")
        cla_bd = self.api.get_batch_id()
        self.log.info("  cla_bd = %s", cla_bd)

        self.log.info("🪙 [2/3] evento gg_clse (ad fechado, em=%s)...", em_clse)
        ev_clse = self.api.ad_closed(em_clse)

        self.log.info("🪙 [3/3] evento gg_lad (ad carregado, em=%s)...", em_lad)
        ev_lad = self.api.ad_loaded(em_lad, cla_bd or "")

        return {"cla_bd": cla_bd, "gg_clse": ev_clse, "gg_lad": ev_lad}

    def ciclo_credito(self, cla_em: str, cla_bad: str, cla_jsc: float) -> Dict[str, Any]:
        """
        Sequência completa de crédito (rotas da captura anterior).
        Requer ids de um ad REAL assistido. Sem isso, o servidor rejeita.
        """
        self.log.info("🪙 Passo 1/3: saldo antes...")
        antes = self.api.wallet()

        self.log.info("🪙 Passo 2/3: batch id da sessão...")
        cla_bd = self.api.get_batch_id()

        self.log.info("🪙 Passo 3/3: enviando crédito...")
        resp = self.api.credit_gold(cla_bd or "", cla_em, cla_bad, cla_jsc)

        self.log.info("🪙 Stats da sessão:")
        self.api.session_stats()
        return {"antes": antes, "credito": resp}

    def painel(self):
        """Painel read-only: saldo + stats da sessão."""
        self.consultar_saldo()
        self.api.session_stats()


if __name__ == "__main__":
    log.info("=========== GOLD FLOW (MODE=%s) ===========", MODE.upper())
    flow = GoldFlow()
    flow.fluxo_captura()   # <- mesmo fluxo da captura
    flow.painel()
    log.info("=========== FIM ===========")
