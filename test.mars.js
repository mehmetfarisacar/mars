MARS.log("mars script loaded");
var r = MARS.shell("id");
MARS.log(r);
var files = MARS.shell("ls /data/local/tmp");
MARS.log(files);
