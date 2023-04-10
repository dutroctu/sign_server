function responseOK(data) {
    console.log("responseOK")
    console.log(data);
    var dialog = document.getElementById('dialog');
    var dialogContent = document.getElementById('dialogContent');
    if (typeof data === 'string')
        dialogContent.textContent = "something when wrong.. are you login first?"
    else
        dialogContent.textContent = data.message;
    dialog.style.display='block'
    showLoading(false)
    var dialogReload = document.getElementById('dialogReload');
    dialogReload.style.display='block'
}


function add_policy()
{
    showLoading(true)
    keyid = document.getElementById('id').value
    username = document.getElementById('username').value
    remoteIP = document.getElementById('remoteIP').value
    action = document.getElementById('action').value
    rsa = document.getElementById('rsa').value
    // $.ajax({
    //     url: `/add_policy/${keyid}`,
    //     method: 'POST',
    //     cache: false,
    //     contentType: false,
    //     processData: false,
    //     data: form_data,
    //     success: onResponseOK,
    //     error: onResponseError
    // });

    var dict = {
        username : username,
        remoteIP : remoteIP,
        action : action,
        rsa : rsa
        };
    $.ajax({
        url: `/add_policy/${keyid}`,
        method: 'POST',
        data : JSON.stringify(dict),
        contentType: "application/json",
        success: responseOK,
        error: onResponseError
    });

}

function del_policy()
{
    showLoading(true)
    keyid = document.getElementById('id').value

    var dict = {
        };
    $.ajax({
        url: `/del_policy/${keyid}`,
        method: 'POST',
        data : JSON.stringify(dict),
        contentType: "application/json",
        success: responseOK,
        error: onResponseError
    });

}
// $(function(){
//     $('#add_policy').on('submit', add_policy);
// });