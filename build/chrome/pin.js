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
}, 1);
