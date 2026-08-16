<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:py="http://qeeqbox.com/python"
    exclude-result-prefixes="py">
    <xsl:output method="html" indent="yes"/>
    <xsl:template match="/config">
        <html>
            <form class="box-border-style" id="target-section" method="post">
              <div class="div-header">
                <div class="div-left">Settings</div>
              </div>
              <div class="div-100-grid-row-gap" id="config-results">
                <div id="Settings-results">
                    <div>Port: <xsl:value-of select="/config/port"/></div>
                    <div>IP: <xsl:value-of select="/config/ip"/></div>
                    <div>Database File: <xsl:value-of select="/config/database-file"/></div>
                    <div>External Folder: <xsl:value-of select="/config/external-folder"/></div>
                    <div>Template Folder: <xsl:value-of select="/config/template-folder"/></div>
                    <div>Logs Folder: <xsl:value-of select="/config/logs-folder"/></div>
                    <div>Logs File: <xsl:value-of select="/config/logs-file"/></div>
                    <div>Config File: <xsl:value-of select="/config/config-file"/></div>
                    <div>Config Style File: <xsl:value-of select="/config/template-folder"/>/<xsl:value-of select="/config/config-style"/></div>
                    <div>Timezone: <xsl:value-of select="/config/timezone"/></div>
                </div>
                <xsl:if test="edit = 'true'">
                <div class="div-100">
                    <div class="div-100">settings</div>
                    <div class="flex-grow-area contenteditable" contenteditable="plaintext-only" name="config-xml" id="config-xml-text"><xsl:value-of select="py:function('read', string(/config/config-file))"/></div>
                </div>
                <div class="div-100">
                    <div class="div-100">style</div>
                    <div class="flex-grow-area contenteditable" contenteditable="plaintext-only" name="config-xsl" id="config-xsl-text"><xsl:value-of select="py:function('read', concat(/config/template-folder,'/',/config/config-style))"/></div>
                </div>
                <div class="div-100">
                      <input type="submit" formaction="/config" id="config-button" value="validate" />
                </div>
              <script>
                  function update_settings(settings,style) {
                    $.ajax({
                        url : "config",
                        type : "post",
                        data: {"config-xml":settings,"config-xsl":style},
                        success:function(data){
                          if (data !== 'Error') {
                            $('#Settings-results').html(data)
                          }
                        },
                    }); 
                  }

                  $('#config-button').on('click', function(e) {
                    e.preventDefault()
                    update_settings($('#config-xml-text').text(),$('#config-xsl-text').text())
                    })
               </script>
             </xsl:if>
              <xsl:if test="edit = 'false'">
                  <div class="div-100">
                    <div class="div-100">Timezone</div>
                          <input type="text" class="flex-grow-area" name="config-timezone" id="config-timezone-text" placeholder="Enter timezone" >
                            <xsl:attribute name="value">
                                <xsl:value-of select="/config/timezone" />
                            </xsl:attribute>
                          </input>
                </div>
                <div class="div-100">
                      <input type="submit" formaction="/config" id="config-button" value="Update" />
                </div>
              <script>
                  function update_settings(timezone) {
                    $.ajax({
                        url : "config",
                        type : "post",
                        data: {"config-timezone":"<timezone>"+timezone+"</timezone>"},
                        success:function(data){
                          if (data !== 'Error') {
                            location.reload();
                          }
                        },
                    }); 
                  }

                $('#config-button').on('click', function(e) {
                  e.preventDefault()
                  update_settings($('#config-timezone-text').val())
                  })
               </script>
              </xsl:if>
             </div>
            </form>
        </html>
    </xsl:template>
</xsl:stylesheet>