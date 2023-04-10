
function showLoading(show){
    var dialog = document.getElementById('loader');
    dialog.style.display= show?'block':'none'
}

function response(data) {
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
    var i;
    var total = 3
    var ok = 0

    showLoading(true)
    $.ajax({
        url:  `/help/${help_id}`,
        method: 'POST',
        success: response,
        error: response
    });

}


function get_command_help(tool)
{
    command = document.getElementById('command')
    if (command != null){
        commandid = command.value
        showLoading(true)
        $.ajax({
            url: `/genkey/${tool}?help=${commandid}`,
            method: 'POST',
            contentType: "application/json",
            success: response,
            error: response
        });
    }
    else
    {
        alert("not found 'command'")
    }

}
