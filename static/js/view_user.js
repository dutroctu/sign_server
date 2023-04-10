
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

function AddRsa(userid)
{
    showLoading(true)
    rsa = document.getElementById('txtRsa').value
    var dict = {userid : userid, rsa : rsa};
    $.ajax({
        url: '/add_rsa',
        method: 'POST',
        data : JSON.stringify(dict),
        contentType: "application/json",
        success: responseOK,
        error: onResponseError
    });
}

function DeleteRsa(userid, rsa)
{
    showLoading(true)
    var dict = {userid : userid, rsa : rsa};
    $.ajax({
        url: '/del_rsa',
        method: 'POST',
        data : JSON.stringify(dict),
        contentType: "application/json",
        success: responseOK,
        error: onResponseError
    });

}
// $(function(){
//     $('#edit_user').on('submit', edit_user);
// });