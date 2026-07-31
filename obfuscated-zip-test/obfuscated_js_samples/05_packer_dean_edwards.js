// Dean Edwards Packer (classic eval + dictionary / base62 style)
// Original idea roughly equivalent to:
//   function sum(args){var result=0;for(var i=0;i<args.length;++i)result+=args[i];return result;}
//   console.log(sum(10,20,30));
// Packed form (illustrative public example style):

eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('6 4(2){5 3=0;7(5 1=0;1<2.8;++1)3+=2[1];9 3}a.b(4(c,d,e))',15,15,'|i|arguments|result|sum|var|function|for|length|return|console|log|10|20|30'.split('|'),0,{}));
