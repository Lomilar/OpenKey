function clickOk() {
	parentWindow.pinWindowPINValue = document.getElementById('pin').value;

	window.close();

	return;
}

function clickCancel() {
	window.close();

	return;
}

function focusPin() {
	window.focus();

	document.getElementById('pin').focus();

	return;
}

setTimeout(function() {
	var noFocusObjects, idx;

	document.getElementById('ok').onclick = function() {
		clickOk();
	};

	document.getElementById('cancel').onclick = function() {
		clickCancel();
	};

	window.onfocus = function() {
		focusPin();
	}

	document.getElementById('pin').onblur = function() {
		setTimeout(function() {
			if (document.activeElement.className != "button") {
				focusPin();
			}
		}, 1);
	}

	document.getElementById('pin').onkeypress = document.getElementById('pin').onkeyup = function(keyEvent) {
		var tryKeyPressed;
		var keyPressed;
		var idx;

		if (!keyEvent) {
			return(true);
		}

		tryKeyPressed = [];

		if (keyEvent.keyIdentifier) {
			tryKeyPressed.push(keyEvent.keyIdentifier);
		}

		if (keyEvent.code) {
			tryKeyPressed.push(keyEvent.code);
		}

		for (idx = 0; idx < tryKeyPressed.length; idx++ ) {
			keyPressed = tryKeyPressed[idx];

			switch (keyPressed) {
				case "Enter":
					clickOk();

					return(false);
				case "Escape":
					clickCancel();

					return(false);
			}
		}

		return(true);
	};
}, 1);
