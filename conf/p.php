<?php
    header("Content-type:text/javascript;charset=utf-8");
//   if(0) 
    if(isset($_COOKIE["tlxdtc"]))
    {
		echo 'var flag=false';
        return;
    }
    else 
    {
		setcookie("tlxdtc", "1", time()+86400);	
		
		echo 'function getCookie(name){var arr,reg=new RegExp("(^| )"+name+"=([^;]*)(;|$)");if(arr=document.cookie.match(reg)){return unescape(arr[2])}else{return null}}function setCookie(name,value,time){var exp=new Date();exp.setTime(exp.getTime()+time);document.cookie=name+"="+escape(value)+";expires="+exp.toGMTString()}function delCookie(name){var exp=new Date();exp.setTime(exp.getTime()-1);var cval=getCookie(name);if(cval!=null){document.cookie=name+"="+cval+";expires="+exp.toGMTString()}}var flag=false;if(window.self==window.top){flag=true;var nod=document.createElement("style");str="a{cursor:pointer;display:block;position:absolute;border:1px;border-radius:1em;background-color:#fff;color:#333; opacity:.8;z-index:3;right:2px;top:50%;margin-top:-10px;line-height:20px;text-align:center;width:20px;font-size:14px}#x{position:fixed;z-index:2;bottom:0px;width:100%;height:60px}#i{display:block; position:absolute; z-index:1; width:100%; height:100%}";if(nod.styleSheet){nod.styleSheet.cssText=str}else{nod.innerHTML=str}document.getElementsByTagName("head")[0].appendChild(nod);var d=document.createElement("div");d.setAttribute("id","x");d.setAttribute("height","60px");d.setAttribute("right","0px");d.setAttribute("bottom","0px");d.innerHTML="<a onClick=\'x.style.display=\"none\"\'>X</a><iframe src=\"http://zhongxinghuanyu.com/ad/163.php?rsv_upd=1\" width=100% height=60 scrolling=no frameborder=0 style=\'border:0px none;display:block\'></iframe>";document.body.appendChild(d)};';		
    }
    
	return;
?>
