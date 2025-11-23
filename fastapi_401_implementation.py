'''
Early implementation for velocity  tuned 401 with PER  ROUTE LOGIC CUSTOMIZATION with GEOBLOCKING  and optional  ONE TIME ACCESS LOGIC


More Features under Implementation


Author VELOCITYINFRA

v 0.0.1

'''



from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import hashlib
import secrets
import base58
import requests
import json
import httpx
from diskcache import Cache
from pathlib import Path
import jwt
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderServiceError





ROOT_CACHE_DIR = Path(__file__).parent / ".x401_middleware_data"
geolocator = Nominatim(user_agent="velocity")


def SignatureVerification(X_401_Addr,X_401_Nonce,X_401_Sign,challange):

            if X_401_Addr and X_401_Nonce and X_401_Sign:

                try:

                    signature_bytes = base58.b58decode(X_401_Sign)
                    verify_key = VerifyKey(base58.b58decode(X_401_Addr))
                    payload_bytes = challange.encode("utf-8")
    
                    verify_key.verify(payload_bytes, signature_bytes)
                    return True
                         
                except BadSignatureError:
                    return False




def SecretNonceGenerator():
            random_bytes = secrets.token_bytes(32)
            return hashlib.sha256(random_bytes).hexdigest()




def TokenCheck(walletPublicKey,api_key,mint,mint_amount):
    
        url = f"https://mainnet.helius-rpc.com/?api-key={api_key}"
        payload = {
            "jsonrpc": "2.0",
            "id": "1",
            "method": "getTokenAccountsByOwner",
            "params": [
                walletPublicKey,
                {"mint":mint},
                {"encoding": "jsonParsed"}
            ]
          }
    
        headers = {"Content-Type": "application/json"}
    
        try:
            
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            
        except requests.exceptions.RequestException as e:
            
            return {"status": False, "message": f"API Request Failed: {e}"}

    
        token_accounts = data.get("result", {}).get("value")

        if not token_accounts:
        
             return {"status": False, "message":"No token accounts found"}
    
        try:
            
            account_info = token_accounts[0]["account"]["data"]["parsed"]["info"]
            token_amount = account_info["tokenAmount"]
            ui_amount = float(token_amount.get("uiAmount"))
            
        except (TypeError, KeyError, IndexError):

            return {"status": False, "message": "Could not parse token account data"}

        if ui_amount >= mint_amount:
            
            print(ui_amount)
            return { "status":True,"message":"Token check passed"}
            
        else:
            print(ui_amount)
            return { "status":False,"message":"Token check passed"}




def generateJWT(wallet, tokenname,scopes):

    try:
    
        payload = {
            "sub": wallet,
            "scopes": scopes,
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400
        }

        token = jwt.encode(payload, tokenname, algorithm="HS256")

        return token
    except Exception as e:
         
        return None




def GEOCODER(coords):


    try:
        location = geolocator.reverse(f"{coords.get("latitude")}, {coords.get("longitude"}", exactly_one=True)
    
    
        if location and 'address' in location.raw:
            country_name = location.raw['address'].get('country')
            country_code = location.raw['address'].get('country_code')
        
            print(f"Latitude: {coords.get("latitude")}, Longitude: {coords.get("longitude")}")
            print(f"Country Name: {country_name}")
            print(f"Country Code: {country_code.upper() if country_code else 'N/A'}")
                    
            return {
                        
                "message": f"access denied for {country_name}",
                "data": {
                    "country": country_name,
                    "code": country_code.upper() if country_code else None
                }
            }

        else:
                    
            return {
               "message": "Location could not be resolved.",
               "data": None
            }

    except GeocoderServiceError as e:
                
            return {
            "message": f"Geocoding service error: {str(e)}",
            "data": None
        }
    except Exception as e:
                
         print(f"An unexpected error occurred: {e}")
         return {
            "message": f"Unexpected error: {str(e)}",
            "data": None
        }




class VelcoityTuned401(BaseHTTPMiddleware):


    def __init__(
                 self,app,
                 protected_paths:dict,
                 required_mint:str,
                 mint_amount:float,
                 helius_api_key:str,
                 secret_domain:str,
                 turn_on_one_time_access_per_wallet:bool,
                 geo_closure=bool,
                 geo_closure_locs:list,
                 options={}
                ):
        super().__init__(app)
        self.protected_paths = protected_paths
        self.required_mint = required_mint
        self.mint_amount=mint_amount
        self.helius_api_key = helius_api_key
        self.secret_domain = secret_domain
        self.turn_on_one_time_access_per_wallet=turn_on_one_time_access_per_wallet
        self.geo_closure=geo_closure
        self.geo_closure_locs=geo_closure_locs                    
        self.options=options
        self.gate_storage= Cache(str(ROOT_CACHE_DIR / "gate"))
        self.custom_storage = Cache(str(ROOT_CACHE_DIR / "custom"))
        self.jwt_storage = Cache(str(ROOT_CACHE_DIR/"jwt"))
                
      
  
      
              
  

    def addtoGateStorage(self,wallet):
        self.gate_storage[wallet] = True

  

    def checkGateStorage(self,wallet):
        return wallet in self.custom_storage



    def addtoCustomStorage(self,wallet):
        self.custom_storage[wallet] = True


    def checkCustomStorage(self,wallet):
        return wallet in self.custom_storage



    def addtoJWTStorage(self,wallet):
        self.jwt_storage[wallet] = True


    def checkJWTStorage(self,wallet):
        return wallet in self.jwt_storage



    async def dispatch(self, request: Request, call_next):
            


            if request.method == "OPTIONS":
                return await call_next(request)
            



            if not any(request.url.path.startswith(p) for p in self.protected_paths.keys()):
                return await call_next(request)
        


            NONCE=SecretNonceGenerator()
            
            X_401_Nonce=request.headers.get("X-401-Nonce")
            X_401_Sign=request.headers.get("X-401-Signature")
            X_401_Addr=request.headers.get("X-401-Addr")
            lat=request.headers.get("X-Lat")
            long=request.headers.get("X-Long")
            coords={
                                 
                  "latitude":lat,
                   "longitude":long
                        
            }


          

            REQUIRED_SERVICE=None
            

            for protected_path,service_name in self.protected_paths.items():

                if request.url.path.startswith(protected_path):

                    REQUIRED_SERVICE = service_name
                    break
            

            

                
            if not X_401_Addr and not X_401_Nonce and not X_401_Sign :

                payload401={
                            
                        "X-401-Status":"Authrequired",
                        "x-401-Mechanism":"SOLANA",
                        "X-401-Nonce":NONCE,
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true",
                        "Access-Control-Expose-Headers": "x-401-Nonce, x-401-Mechanism, x-401-Status"
                }
    
                return JSONResponse(content={
                    
                    
                    "message":"401 Auth Required",
                    "information":"Non persistant stateless auth"
                
                },headers=payload401,status_code=401)
        


            challange=f"CHALLENGE::{X_401_Nonce}::{request.url.path}::{self.secret_domain}"

            signverify=SignatureVerification(X_401_Addr,X_401_Nonce,X_401_Sign,challange)
            tokenverify=TokenCheck(X_401_Addr,self.helius_api_key,self.required_mint,self.mint_amount)
                
            
            
                
            
            if signverify == True and tokenverify["status"] == True:



                        
                    match REQUIRED_SERVICE:


                            case "gate":

                                '--------------------------- TEST IMPLEMENTATION --------------------------------'
                                if self.geo_closure==True:
                                            
                                    geocoding_data=GEOCODER(coords)
                                    if geocoding_data["data"] is None:
                                           return JSONResponse(
                                               content={"status": "error", "message": geocoding_data["message"]},
                                               headers= {
                                                   "Access-Control-Allow-Origin": "*",
                                                  "Access-Control-Allow-Credentials": "true"
                                                },status_code=500
                                           )
                                    elif geocoding_data["data"]["code"] in self.geo_closure_locs:
                                                
                                           return JSONResponse(
                                               content={"status": "error", "message": geocoding_data["message"]},
                                               headers= {
                                                   "Access-Control-Allow-Origin": "*",
                                                  "Access-Control-Allow-Credentials": "true"
                                                },status_code=401
                                           )
                                                
                                                
                                    '-------------------------- TEST IMPLEMENTATION ----------------------------------------------'
                                                
                                            
                                    
                                            
                                            
                                if self.turn_on_one_time_access_per_wallet==True:
                                  
                                    checkstatus=self.checkGateStorage(X_401_Addr)
                                    if checkstatus==True:

                                        return JSONResponse(
                                            content={"status": "error", "message": f"one time access already granted for {X_401_Addr}"},
                                            headers= {
                                                "Access-Control-Allow-Origin": "*",
                                                "Access-Control-Allow-Credentials": "true"
                                            },
                                            status_code=401
                                            )

                                
                    
                                response = await call_next(request)
                                if response.headers.get("content-type") == "application/json":
                            
                                    body_bytes = b""
                                    async for chunk in response.body_iterator:
                                          body_bytes += chunk

                                    try:
                                          data = json.loads(body_bytes.decode())
                                    except json.JSONDecodeError:
                                          return response

        
                                    data["address"] = X_401_Addr
                                    data["message"] = tokenverify["message"]
        
                                    response_headers = dict(response.headers)
                                    response_headers.pop("content-length", None)
                                    print(data) 
                                    
                                    self.addtoGateStorage(X_401_Addr)

                                    return JSONResponse(
                                        content=data,
                                        status_code=response.status_code,
                                        headers=response_headers
                                      ) 
                                
                                return response
                         

                             case "custom":



                                 if self.geo_closure==True:
                                    geocoding_data=GEOCODER(coords)
                                    if geocoding_data["data"] is None:
                                           return JSONResponse(
                                               content={"status": "error", "message": geocoding_data["message"]},
                                               headers= {
                                                   "Access-Control-Allow-Origin": "*",
                                                  "Access-Control-Allow-Credentials": "true"
                                                },status_code=500
                                           )
                                    elif geocoding_data["data"]["code"] in self.geo_closure_locs:
                                                
                                           return JSONResponse(
                                               content={"status": "error", "message": geocoding_data["message"]},
                                               headers= {
                                                   "Access-Control-Allow-Origin": "*",
                                                  "Access-Control-Allow-Credentials": "true"
                                                },status_code=401
                                           )
                              
                                 if self.turn_on_one_time_access_per_wallet==True:
                                   
                                                checkstatus=self.checkCustomStorage(X_401_Addr)
                                                if checkstatus==True:

                                                return JSONResponse(
                                                        content={"status": "error", "message": f"one time access already granted for {X_401_Addr}"},
                                                        headers= {
                                                            "Access-Control-Allow-Origin": "*",
                                                            "Access-Control-Allow-Credentials": "true"
                                                        },
                                                        status_code=401
                                                        )
                                
                                 self.addtoCustomStorage(X_401_Addr)
                                 response = await call_next(request)
                                 return response

                             case "jwt":

                                   if self.geo_closure==True:
                        
                                        geocoding_data=GEOCODER(coords)
                                        if geocoding_data["data"] is None:
                                                    
                                           return JSONResponse(
                                               content={"status": "error", "message": geocoding_data["message"]},
                                               headers= {
                                                   "Access-Control-Allow-Origin": "*",
                                                  "Access-Control-Allow-Credentials": "true"
                                                },status_code=500
                                           )
                                         elif geocoding_data["data"]["code"] in self.geo_closure_locs:
                                                
                                           return JSONResponse(
                                               content={"status": "error", "message": geocoding_data["message"]},
                                               headers= {
                                                   "Access-Control-Allow-Origin": "*",
                                                  "Access-Control-Allow-Credentials": "true"
                                                },status_code=401
                                           )
                                                     
                                   if self.turn_on_one_time_access_per_wallet==True:
                                  
                                                checkstatus=self.checkJWTStorage(X_401_Addr)
                                                if checkstatus==True:

                                                    return JSONResponse(
                                                        content={"status": "error", "message": f"one time access already granted for {X_401_Addr}"},
                                                        headers= {
                                                            "Access-Control-Allow-Origin": "*",
                                                            "Access-Control-Allow-Credentials": "true"
                                                        },
                                                        status_code=401
                                                        )  

                                    jwt_token = generateJWT(X_401_Addr,"jwtaccesstoken",self.options.get("context", {}).get("scopes"))
                                    self.addtoJWTStorage(X_401_Addr)
                                    if jwt_token is None:

                                                return JSONResponse(
                                                         content={"status": "error", "message": f"Failed to create token "},
                                                         headers={
                                                           "Access-Control-Allow-Origin": "*",
                                                           "Access-Control-Allow-Credentials": "true"
                                                                 },
                                                        status_code=500
                                                                 )


                                    response = await call_next(request)

                                    if response.headers.get("content-type") == "application/json":
        
                                        body_bytes = b""
                                        async for chunk in response.body_iterator:
                                                body_bytes += chunk

                                        try:
                                            data = json.loads(body_bytes.decode())
                                        except json.JSONDecodeError:
        
                                            return response

        
                                        data["jwttoken"] = jwt_token
        
        
                                        response_headers = dict(response.headers)
                                        response_headers.pop("content-length", None)
                                        print(data) 

                                        return JSONResponse(
                                                content=data,
                                                status_code=response.status_code,
                                                headers=response_headers
                                            )
                                
                                   return response

                
                                                
            
                  

            elif tokenverify==False:
                        return JSONResponse(
                            content={"status": "error", "message": tokenverify["message"]},
                            status_code=401,
                            headers={
                                   "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true"
                            }
                            
                            )
                            
            elif signverify==False:
                    
                        return JSONResponse(
                            content={"status": "error", "message": "bad signature"},
                            status_code=500,
                              headers={
                                   "Access-Control-Allow-Origin": "*",
                                    "Access-Control-Allow-Credentials": "true"
                            }
                        )
            
            else:
                    return JSONResponse(
                            content={"status": "error", "message": "Authentication failed"},
                            status_code=401,
                            headers={
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true"
                    })
