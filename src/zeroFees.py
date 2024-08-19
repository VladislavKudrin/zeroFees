import json
from blockfrost import ApiUrls
from pycardano import Address, Network, PaymentVerificationKey, BlockFrostChainContext, HDWallet, TransactionInput, TransactionOutput, Value, utils, TransactionBody, PaymentExtendedSigningKey, VerificationKeyWitness, PaymentExtendedVerificationKey, Transaction, TransactionWitnessSet
import requests
import os
from dotenv import load_dotenv

load_dotenv(override=True)

BLOCKFROST_PROJECT_ID = os.getenv("BLOCKFROST_PROJECT_ID")
FEE = int(os.getenv("FEE"))
SEND_AMOUNT = int(os.getenv("SEND_AMOUNT"))
FEE_IN_TOKENS = int(os.getenv("FEE_IN_TOKENS"))
TOKEN_POLICY_ID = os.getenv("TOKEN_POLICY_ID")
TOKEN_NAME = os.getenv("TOKEN_NAME")
MNEMONIC_SEND = os.getenv("MNEMONIC_SEND")
MNEMONIC_FEE_PAYER = os.getenv("MNEMONIC_FEE_PAYER")
TO_ADDRESS = os.getenv("TO_ADDRESS")
FROM_ADDRESS = os.getenv("FROM_ADDRESS")

def get_address_utxos(address):
  headers = {
    "project_id": BLOCKFROST_PROJECT_ID,
    "Content-Type": "application/json",
  }
  response = requests.get("{blockfrost_url}/addresses/{address}/utxos".format(blockfrost_url="https://cardano-preprod.blockfrost.io/api/v0", address=address), headers=headers)
  return response.json()

def get_valid_utxos(address, unit, token_amount):
  utxos = get_address_utxos(address=address)
  valid_utxos = []
  
  for utxo in utxos:
    for amount in utxo['amount']:
      if amount['unit'] == unit and int(amount['quantity']) >= int(token_amount):
        valid_utxos.append(utxo)
  
  return valid_utxos[0]

def calculate_fee_for_output(address, policyId, tokenName, amount):
  if policyId and tokenName:
    output = TransactionOutput(address, Value.from_primitive([
        0, 
        {
            policyId: {
                tokenName: amount,
            }
        },
    ]))
  else: 
    output = TransactionOutput(address, amount)
    
  return utils.min_lovelace(context, output)

def calculate_tx_fee(inputs, outputs):
  tx_body = TransactionBody(inputs=inputs, outputs=outputs, fee=0)
  return utils.fee(context, len(tx_body.to_cbor().hex()))



network = Network.TESTNET
context = BlockFrostChainContext(BLOCKFROST_PROJECT_ID, base_url=ApiUrls.preprod.value)

#IF ADDRESS IS NOT DEFINED THEN TAKE MNEMONIC AND DERIVE THE ADDRESS
if len(FROM_ADDRESS) == 0 and len(MNEMONIC_SEND) > 0:
  hdw = HDWallet.from_mnemonic(MNEMONIC_SEND)
  hdwallet_spend = hdw.derive_from_path("m/1852'/1815'/0'/0/0")
  spend_public_key = hdwallet_spend.public_key
  spend_private_key = hdwallet_spend.xprivate_key
  hdwallet_stake = hdw.derive_from_path("m/1852'/1815'/0'/2/0")
  stake_public_key = hdwallet_stake.public_key
  spend_vk = PaymentExtendedVerificationKey.from_primitive(spend_public_key)
  stake_vk = PaymentVerificationKey.from_primitive(stake_public_key)
  spend_sk = PaymentExtendedSigningKey.from_primitive(spend_private_key)
  send_address = Address(spend_vk.hash(), stake_vk.hash(), network=Network.TESTNET)
else:
  send_address = Address.decode(FROM_ADDRESS)

#DEFINE HDWALLET FOR FEE PAYER
hdw_fee = HDWallet.from_mnemonic(MNEMONIC_FEE_PAYER)

hdwallet_fee = hdw_fee.derive_from_path("m/1852'/1815'/0'/0/0")
spend_public_key_fee = hdwallet_fee.public_key
spend_private_key_fee = hdwallet_fee.xprivate_key
hdwallet_stake_fee = hdw_fee.derive_from_path("m/1852'/1815'/0'/2/0")
stake_public_key_fee = hdwallet_stake_fee.public_key


# DEFINE KEYS
spend_vk_fee = PaymentExtendedVerificationKey.from_primitive(spend_public_key_fee)
stake_vk_fee = PaymentVerificationKey.from_primitive(stake_public_key_fee)
spend_sk_fee = PaymentExtendedSigningKey.from_primitive(spend_private_key_fee)

#DEFINE ADDRESSES
fee_address = Address(spend_vk_fee.hash(), stake_vk_fee.hash(), network=Network.TESTNET)
to_address = Address.decode(TO_ADDRESS)

#CALCULATE TOKEN SEND FEE
send_address_fee = calculate_fee_for_output(to_address, TOKEN_POLICY_ID, TOKEN_NAME, SEND_AMOUNT + FEE_IN_TOKENS)

#GET VALID SENDER UTXOS
valid_sender_utxo = get_valid_utxos(send_address, TOKEN_POLICY_ID+TOKEN_NAME, SEND_AMOUNT + FEE_IN_TOKENS)

#DEFINE SENDER INPUTS
tx_in_sender_inputs = TransactionInput.from_primitive([valid_sender_utxo["tx_hash"], valid_sender_utxo["tx_index"]])

#GET INPUT FROM FEE PAY ADDRESS
valid_fee_utxo = get_valid_utxos(fee_address, "lovelace", FEE)

#DEFINE FEE PAYER INPUTS
tx_in_fee_input = TransactionInput.from_primitive([valid_fee_utxo["tx_hash"], valid_fee_utxo["tx_index"]])

# #DEFINE OUTPUTS
send_address_output_tokens = TransactionOutput(to_address, Value.from_primitive([
        send_address_fee, 
        {
            TOKEN_POLICY_ID: {
                TOKEN_NAME: SEND_AMOUNT,
            }
        },
    ]))

send_address_change = TransactionOutput(send_address, Value.from_primitive([
        sum(int(amount["quantity"]) for amount in valid_sender_utxo["amount"] if amount["unit"] == "lovelace"),
        {
            TOKEN_POLICY_ID: {
                TOKEN_NAME: sum(int(amount["quantity"]) for amount in valid_sender_utxo["amount"] if amount["unit"] == TOKEN_POLICY_ID+TOKEN_NAME) - SEND_AMOUNT - FEE_IN_TOKENS,
            }
        },
    ]))

#DEFINE FEE TEMPLATE TO CALCULATE FEE
fee_address_change_template = TransactionOutput(send_address, Value.from_primitive([
        sum(int(amount["quantity"]) for amount in valid_fee_utxo["amount"] if amount["unit"] == "lovelace"),
        {
          **{
            amount["unit"][:56]: {
                amount["unit"][56:]: int(amount["quantity"])
            }
            for amount in valid_fee_utxo["amount"]
            if amount["unit"] != "lovelace" and amount["unit"] != TOKEN_POLICY_ID + TOKEN_NAME
          },
          TOKEN_POLICY_ID: {
              TOKEN_NAME: sum(int(amount["quantity"]) for amount in valid_fee_utxo["amount"] if amount["unit"] == TOKEN_POLICY_ID + TOKEN_NAME) + FEE_IN_TOKENS
          }},
    ]))

tx_fee = calculate_tx_fee([tx_in_sender_inputs, tx_in_fee_input], [send_address_output_tokens, send_address_change, fee_address_change_template])

#REAL FEE OUTPUT
fee_address_change = TransactionOutput(fee_address, Value.from_primitive([
        sum(int(amount["quantity"]) for amount in valid_fee_utxo["amount"] if amount["unit"] == "lovelace") - tx_fee - send_address_fee, 
        {
          **{
            amount["unit"][:56]: {
                amount["unit"][56:]: int(amount["quantity"])
            }
            for amount in valid_fee_utxo["amount"]
            if amount["unit"] != "lovelace" and amount["unit"] != TOKEN_POLICY_ID + TOKEN_NAME
          },
          TOKEN_POLICY_ID: {
              TOKEN_NAME: sum(int(amount["quantity"]) for amount in valid_fee_utxo["amount"] if amount["unit"] == TOKEN_POLICY_ID + TOKEN_NAME) + FEE_IN_TOKENS
          }},
    ]))

#REAL TX
tx_body = TransactionBody(inputs=[tx_in_sender_inputs, tx_in_fee_input], outputs=[send_address_output_tokens, send_address_change, fee_address_change], fee=tx_fee)
fee_address_signature = spend_sk_fee.sign(tx_body.hash())

vk_witnesses = [VerificationKeyWitness(spend_vk_fee, fee_address_signature)]

#IF MNEMONIC SEND IS DEFINED THEN SIGN WITH IT
if len(FROM_ADDRESS) == 0 and len(MNEMONIC_SEND) > 0:
  send_address_signature = spend_sk.sign(tx_body.hash())
  vk_witnesses.append(VerificationKeyWitness(spend_vk, send_address_signature))

signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

# #CBOR FOR ETERNL
print(signed_tx.to_cbor().hex())

