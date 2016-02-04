#include "ppapi/cpp/module.h"

class CACKeyModule : public pp::Module {
	public:
		CACKeyModule(): pp::Module() {}
		virtual ~CACKeyModule() {}

		virtual pp::Instance *CreateInstance(PP_Instance instance) {
			return(NULL);
		}
};

namespace pp {
	Module *CreateModule() {
		return(NULL);
	}
}
