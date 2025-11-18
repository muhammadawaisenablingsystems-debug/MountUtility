window.triggerFileDownloadUrl = function (url) {
    const a = document.createElement('a');
    a.href = url;
    a.download = "";  // let the server decide filename
    document.body.appendChild(a);
    a.click();
    a.remove();
};