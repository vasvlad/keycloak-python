#!/usr/bin/python
# -*- coding: utf-8 -*-

import falcon
import logging
from keycloak import Keycloak
from keycloak.http_api.falcon import FalconAPI
import logging

from nameko.standalone.rpc import ClusterRpcProxy
CONFIG = {'AMQP_URI': "amqp://guest:guest@rabbitmq-prod.oblgaz"}
#CONFIG = {'AMQP_URI': "amqp://guest:guest@rabbitmq.oblgaz"}

import sys




class Resource(object):
    def __init__(self, protect=False):
        self.keycloak = None
        if protect:
            self.keycloak = Keycloak(FalconAPI())

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        if self.keycloak:
            grant = self.keycloak.get_grant(req, resp)

            if self.keycloak.grant_has_role(grant, "qrcode_writer"):
                resp.body = "has role! token: %s" % self.keycloak.manager.decode_token(grant.access_token)
            else:
                try:
                    resp.body = "No role! token: %s" % self.keycloak.manager.decode_token(grant.access_token)
                except:
                    resp.body = "No valid bearer token."
        else:
            resp.body = """
            Everything a-ok.
            """



class IdentityScopes(object):
    def __init__(self):
        self.keycloak = Keycloak(FalconAPI())

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        if self.keycloak:
            grant = self.keycloak.get_grant(req, resp)
            try:
                resp.body = "%s" % self.keycloak.manager.decode_token(grant.access_token)
            except:
                resp.body = "No valid bearer token."
        else:
            resp.body = """
            Problem
            """

class SetQrCode(object):
    def __init__(self):
        self.keycloak = Keycloak(FalconAPI())

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        if self.keycloak:
            grant = self.keycloak.get_grant(req, resp)
#            doc = json.load(self.keycloak.manager.decode_token(grant.access_token))
#            print (doc[email])

            if grant:
                if self.keycloak.grant_has_role(grant, "qrcode_writer"):
#                    try:
                        qrcode = ""
                        gasbaseuid = ""
                        remote_addr = "0.0.0.0"
                        lat = "0.0"
                        lon = "0.0"
                        accuracy = "0.0"
                        if (req.get_param("qrcode") and req.get_param("gasbaseuid")):
                            qrcode = req.get_param("qrcode")
                            lat = req.get_param("lat")
                            lon = req.get_param("lon")
                            accuracy = req.get_param("accuracy")
                            gasbaseuid = req.get_param("gasbaseuid")
                            _nameko_rpc = ClusterRpcProxy(CONFIG)
                            with _nameko_rpc as rpc:
                                print (qrcode)
                                result = rpc.equipgasb.setLinkObjQRcode(gasbaseuid, qrcode)
                                print (result)
                                print (self.keycloak.manager.decode_token(grant.access_token))
                                if (result == 0):
                                    if (req.remote_addr):
                                        remote_addr = req.remote_addr
                                    logger.warning('Microservice qrcode_writer {remote_addr: "%s", email:"%s", name: "%s", qrcode: "%s", gasbaseuid: "%s", lat: "%s", lon: "%s", accuracy="%s"}', 
                                                remote_addr,
                                                self.keycloak.manager.decode_token(grant.access_token)['email'],
                                                self.keycloak.manager.decode_token(grant.access_token)['name'],
                                                qrcode, gasbaseuid, lat, lon, accuracy)
                                    resp.body = "{'Result' : 'Ok'}"
                                else:
                                    if (result == -3):
                                        resp.body = "{'Result' : 'Error', 'Error': 'No valid string for QR-code'}"
                                    else:
                                        if (result == -2):
                                            resp.body = "{'Result' : 'Error', 'Error': 'Not found gas equipment linked this QR-code in database'}"
                                        else:
                                            if (result == -4):
                                                resp.body = "{'Result' : 'Error', 'Error': 'Not found this QR-code as avialable in qr-code database'}"
                                            else:
                                                if (result == -1):
                                                    resp.body = "{'Result' : 'Error', 'Error': 'This QR-code is exist in database'}"
                                                else:
                                                    resp.body = "{'Result' : 'Error', 'Error': 'Unknown Error'}"
                        else:
                            resp.body ="{'Result' : 'Error', 'Error': 'Bad source data'}"
#                    except:
#                        resp.body ="{'Result' : 'Error', 'Error': 'No valid bearer token.'}"
                else:
                    resp.body = "{'Result' : 'Error', 'Error': 'No role'}"
            else:
                resp.status = falcon.HTTP_401
                resp.body = "{'Result' : 'Error', 'Error': 'No Token Access'}"
        else:
            resp.status = falcon.HTTP_401
            resp.body = """
            Problem
            """
logger = logging.getLogger('tcpserver')
handler = logging.handlers.SysLogHandler(address = '/dev/log')
logger.addHandler(handler)

app = falcon.API()

app.add_route('/unprotected', Resource())
app.add_route('/protected', Resource(True))
app.add_route('/identityscopes', IdentityScopes())
app.add_route('/setqrcode', SetQrCode())
