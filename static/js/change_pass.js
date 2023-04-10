
function change_pass(ev)
{
    var username = document.getElementById("username");
    var oldPass = document.getElementById("oldpassword");
    var newPass = document.getElementById("newpassword");
    var newPass2 = document.getElementById("newpassword2");
    if (username == null || username.value.length == 0 || oldPass == null || oldPass.length == 0 || newPass == null || newPass.length == 0 || newPass2 == null || newPass2.length == 0)
    {
        alert("Please input all information")
        return false
    }
    else if (newPass.value != newPass2.value)
    {
        alert("Password mistmatch")
        return false
    }
    else{

        showLoading(true)
        ev.preventDefault();
        var form_data = new FormData(this)
        $.ajax({
            url: '/changepass',
            method: 'POST',
            cache: false,
            contentType: false,
            processData: false,
            data: form_data,
            success: onResponseOK,
            error: onResponseError
        });
    }
    

}

$(function(){
    $('#change_pass').on('submit', change_pass);
});