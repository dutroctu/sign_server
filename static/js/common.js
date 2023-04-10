
function showLoading(show){
    var dialog = document.getElementById('loader');
    dialog.style.display= show?'block':'none'
}

function onResponseOK(data) {
    console.log("onResponseOK")
    console.log(data);
    var dialog = document.getElementById('dialog');
    var dialogContent = document.getElementById('dialogContent');
    if (typeof data === 'string')
        dialogContent.textContent = "something when wrong.. are you login first?"
    else
        dialogContent.textContent = data.message;
    dialog.style.display='block'
    showLoading(false)
    }

function onResponseError(data) {
    console.log("onResponseError")
    console.log(data);
    var dialog = document.getElementById('dialog');
    var dialogContent = document.getElementById('dialogContent');
    if (typeof data === 'string')
    dialogContent.textContent = "something when wrong.. are you login first?"
    else
        if (data.status == 400)
            dialogContent.textContent = "ERROR: " + data.status + " - " + data.statusText + "\n" + data.responseText
        else{
            dialogContent.textContent = "ERROR: " + data.status + " - " + data.statusText
        }
    dialog.style.display='block'
    showLoading(false)
    }

function onDone()
{
    showLoading(false)
}

function showDialog(val) {
    var dialog = document.getElementById('dialog');
    var dialogContent = document.getElementById('dialogContent');
    dialogContent.textContent = val
    dialog.style.display='block'
}

function responseHelp(data) {
    console.log(data);
    var dialog = document.getElementById('dialog');
    var dialogContent = document.getElementById('dialogContent');
    if (data.code == 0)
        dialogContent.innerHTML = data.message;
    else
    dialogContent.textContent = data.message;
    dialog.style.display='block'
    showLoading(false)
}


function get_help(help_id)
{
    showLoading(true)
    $.ajax({
        url:  `/help/${help_id}`,
        method: 'POST',
        success: responseHelp,
        error: onResponseError
    });

}
