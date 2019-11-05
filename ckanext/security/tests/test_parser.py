from lxml import etree
from lxml.html import document_fromstring

good_doc = u"""
<!DOCTYPE html>
<!--[if IE 7]> <html lang="en-NZ" class="ie ie7"> <![endif]-->
<!--[if IE 8]> <html lang="en-NZ" class="ie ie8"> <![endif]-->
<!--[if IE 9]> <html lang="en-NZ" class="ie9"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="secondary-three" lang="en-NZ"> <!--<![endif]-->
  <head>
  <title>Good friend</title>
  </head>
  <body>
    <h1> Hey wurld!?</h1>
  </body>
</html>
"""



doc = document_fromstring(good_doc)
print(etree.tostring(doc, encoding='unicode', method="html", with_comments=True))