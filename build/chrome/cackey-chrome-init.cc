/*
 * Google's PCSC library requires us to write our module in C++ to initialize
 * it.  This component handles the initialization of our module and handles
 * incoming messages, passing them either to our library (cackey-chrome) or
 * to the PCSC-NaCl library from Google as appropriate.
 */

#include <thread>
#include <ppapi/cpp/instance.h>
#include <ppapi/cpp/module.h>
#include <ppapi/cpp/core.h>
#include <ppapi/cpp/var.h>
#include <ppapi/cpp/var_dictionary.h>
#include <ppapi/cpp/var_array.h>
#include <ppapi/cpp/var_array_buffer.h>

#include "pcsc-nacl.h"
#include "cackey-chrome.h"

class CACKeyInstance : public pp::Instance {
	private:
		pp::Core *corePointer;
	public:
		explicit CACKeyInstance(PP_Instance instance, pp::Core *core) : pp::Instance(instance) {
			corePointer = core;
		}

		virtual ~CACKeyInstance() {}

		virtual void HandleMessageThread(pp::VarDictionary *message) {
			cackey_chrome_returnType signRet;
			char *pinPrompt;
			const char *pin;
			const char *smartcardManagerAppId = NULL;
			unsigned char buffer[8192];
			struct cackey_certificate *certificates, incomingCertificateCACKey;
			pp::VarDictionary *reply;
			pp::VarArray certificatesPPArray;
			pp::VarArrayBuffer *certificateContents, *incomingCertificateContents, *incomingData, *outgoingData;
			pp::Var command;
			const pp::Var *messageAsVar = NULL, *outgoingDataAsVar = NULL;
			int numCertificates, i;
			unsigned long outgoingDataLength;

			/*
			 * Extract the command
			 */
			command = message->Get("command");

			/*
			 * Do the thing we are being asked to do
			 */
			reply = new pp::VarDictionary();

			if (command.AsString() == "init") {
				if (message->HasKey("smartcardManagerAppId")) {
					smartcardManagerAppId = message->Get("smartcardManagerAppId").AsString().c_str();
				}

				pcscNaClInit(this, corePointer, smartcardManagerAppId, "CACKey");

				reply->Set("status", "success");
			} else if (command.AsString() == "listcertificates") {
				numCertificates = cackey_chrome_listCertificates(&certificates);

				certificatesPPArray.SetLength(numCertificates);

				for (i = 0; i < numCertificates; i++) {
					certificateContents = new pp::VarArrayBuffer(certificates[i].certificate_len);

					memcpy(certificateContents->Map(), certificates[i].certificate, certificates[i].certificate_len);

					certificateContents->Unmap();

					certificatesPPArray.Set(i, *certificateContents);

					delete certificateContents;
				}

				cackey_chrome_freeCertificates(certificates, numCertificates);

				reply->Set("status", "success");
				reply->Set("certificates", certificatesPPArray);
			} else if (command.AsString() == "sign") {
				if (!message->HasKey("certificate")) {
					reply->Set("status", "error");
					reply->Set("error", "Certificate not supplied");
				} else if (!message->HasKey("data")) {
					reply->Set("status", "error");
					reply->Set("error", "Data not supplied");
				} else {
					incomingCertificateContents = new pp::VarArrayBuffer(message->Get("certificate"));
					incomingData = new pp::VarArrayBuffer(message->Get("data"));

					if (message->HasKey("pin")) {
						pin = message->Get("pin").AsString().c_str();
					} else {
						pin = NULL;
					}

					incomingCertificateCACKey.certificate = incomingCertificateContents->Map();					
					incomingCertificateCACKey.certificate_len = incomingCertificateContents->ByteLength();					

					outgoingDataLength = sizeof(buffer);

					signRet = cackey_chrome_signMessage(&incomingCertificateCACKey,
						incomingData->Map(), incomingData->ByteLength(),
						buffer, &outgoingDataLength,
						&pinPrompt, pin
					);

					incomingCertificateContents->Unmap();
					incomingData->Unmap();

					delete incomingCertificateContents;
					delete incomingData;

					switch (signRet) {
						case CACKEY_CHROME_OK:
							outgoingData = new pp::VarArrayBuffer(outgoingDataLength);

							memcpy(outgoingData->Map(), buffer, outgoingDataLength);

							outgoingData->Unmap();

							outgoingDataAsVar = new pp::Var(outgoingData->pp_var());

							delete outgoingData;

							reply->Set("status", "success");
							reply->Set("signedData", outgoingDataAsVar);

							delete outgoingDataAsVar;

							break;
						case CACKEY_CHROME_ERROR:
							reply->Set("status", "error");
							reply->Set("error", "Unable to sign data");
							break;
						case CACKEY_CHROME_NEEDLOGIN:
						case CACKEY_CHROME_NEEDPROTECTEDLOGIN:
							messageAsVar = new pp::Var(message->pp_var());

							reply->Set("status", "retry");
							reply->Set("originalrequest", messageAsVar);
							reply->Set("pinprompt", pinPrompt);

							delete messageAsVar;

							break;
					}

					if (pinPrompt != NULL) {
						free(pinPrompt);
					}
				}
			} else {
				reply->Set("status", "error");
				reply->Set("error", "Invalid command");
			}

			/*
			 * If a message ID was sent in the request, include it in the reply
			 */
			if (message->HasKey("id")) {
				reply->Set("id", message->Get("id"));
			}

			/*
			 * Indicate who our message is for
			 */
			reply->Set("target", "cackey");
			reply->Set("command", command);

			/*
			 * Send the reply back to the requestor, hopefully they are waiting for this message
			 */
			PostMessage(*reply);

			delete reply;

			delete message;

			return;
		}

		virtual void HandleMessage(const pp::Var& messagePlain) {
			pp::VarDictionary *message;
			pp::Var target;

			/*
			 * The incoming message must be a dictionary
			 */
			if (!messagePlain.is_dictionary()) {
				pcscNaClHandleMessage(messagePlain);

				return;
			}

			/*
			 * Process the appropriate command from the incoming message
			 */
			message = new pp::VarDictionary(messagePlain);

			/*
			 * Verify that this message is destined for us
			 */
			if (!message->HasKey("target")) {
				delete message;

				/* We don't handle this message, see if PCSC-NaCl does */
				pcscNaClHandleMessage(messagePlain);

				return;
			}

			target = message->Get("target");
			if (target.AsString() != "cackey") {
				delete message;

				/* We don't handle this message, see if PCSC-NaCl does */
				pcscNaClHandleMessage(messagePlain);

				return;
			}

			/*
			 * Determine what we are being asked to do
			 */
			if (!message->HasKey("command")) {
				delete message;

				/* We don't handle this message, see if PCSC-NaCl does */
				pcscNaClHandleMessage(messagePlain);

				return;
			}

			/*
			 * Process the request in another thread
			 */
			std::thread(&CACKeyInstance::HandleMessageThread, this, message).detach();

			return;
		}
};

class CACKeyModule : public pp::Module {
	public:
		CACKeyModule() : pp::Module() {}
		virtual ~CACKeyModule() {}

		virtual pp::Instance *CreateInstance(PP_Instance instance) {
			return(new CACKeyInstance(instance, core()));
		}
};

namespace pp {
	Module *CreateModule() {
		return(new CACKeyModule());
	}
}
