function responsehelp(data) {
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

function import_key(ev)
{
    showLoading(true)
    ev.preventDefault();
    var form_data = new FormData(this)
    var ins = document.getElementById('files').files.length;
				
    for (var x = 0; x < ins; x++) {
        form_data.append("files", document.getElementById('files').files[x]);
    }
    $.ajax({
        url: '/import_key',
        method: 'POST',
        cache: false,
        contentType: false,
        processData: false,
        data: form_data,
        success: onResponseOK,
        error: onResponseError
    });

}

$(function(){
    $('#import_key').on('submit', import_key);
});


function get_import_help()
{
    command = document.getElementById('keytool')
    if (command != null){
        commandid = command.value
        showLoading(true)
        $.ajax({
            url: `/import_key/importkey?help=${commandid}`,
            method: 'POST',
            contentType: "application/json",
            success: responsehelp,
            error: onResponseError
        });
    }
    else
    {
        alert("not found 'command'")
    }

}