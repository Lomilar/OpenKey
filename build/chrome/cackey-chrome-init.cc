/*
 * Google's PCSC library requires us to write our module in C++ (thanks, Google)
 * This library wraps the actual library, written in C.
 */

#include <thread>
#include <ppapi/cpp/instance.h>
#include <ppapi/cpp/module.h>
#include <ppapi/cpp/core.h>
#include <ppapi/cpp/var.h>
#include <ppapi/cpp/var_dictionary.h>
#include <ppapi/cpp/var_array.h>
#include <ppapi/cpp/var_array_buffer.h>

#include <stdio.h>

#include "pcsc-nacl.h"
#include "cackey-chrome.h"

class CACKeyInstance : public pp::Instance {
	private:
		void pcscNaClInitWrapper(pp::Core *core) {
			fprintf(stderr, "Calling pcscNaClInit(%p, %p)\n", this, core);

			pcscNaClInit(this, core);

			fprintf(stderr, "pcscNaClInit terminated\n");
		}
	public:
		explicit CACKeyInstance(PP_Instance instance, pp::Core *core) : pp::Instance(instance) {
			std::thread(&CACKeyInstance::pcscNaClInitWrapper, this, core).detach();
		}

		virtual ~CACKeyInstance() {}

		virtual void HandleMessageThread(pp::VarDictionary *message) {
			int numCertificates, i;
			struct cackey_certificate *certificates;
			pp::VarDictionary *reply;
			pp::VarArray certificatesPPArray;
			pp::VarArrayBuffer *certificateContents;
			pp::Var command;

			/*
			 * Extract the command
			 */
			command = message->Get("command");

			/*
			 * Do the thing we are being asked to do
			 */
			if (command.AsString() == "listcertificates") {
				numCertificates = cackey_chrome_listCertificates(&certificates);

				reply = new pp::VarDictionary();

				certificatesPPArray.SetLength(numCertificates);

				for (i = 0; i < numCertificates; i++) {
					certificateContents = new pp::VarArrayBuffer(certificates[i].certificate_len);

					memcpy(certificateContents->Map(), certificates[i].certificate, certificates[i].certificate_len);

					certificateContents->Unmap();

					certificatesPPArray.Set(i, *certificateContents);
				}

				reply->Set("status", "success");
				reply->Set("certificates", certificatesPPArray);
			} else if (command.AsString() == "sign") {
				reply = new pp::VarDictionary();

				reply->Set("status", "success");
			} else {
				reply = new pp::VarDictionary();

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
			 * Send the reply back to the requestor, hopefully they are waiting for this message
			 */
			PostMessage(*reply);

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

				pcscNaClHandleMessage(messagePlain);

				return;
			}

			target = message->Get("target");
			if (target.AsString() != "cackey") {
				delete message;

				pcscNaClHandleMessage(messagePlain);

				return;
			}

			/*
			 * Determine what we are being asked to do
			 */
			if (!message->HasKey("command")) {
				delete message;

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
