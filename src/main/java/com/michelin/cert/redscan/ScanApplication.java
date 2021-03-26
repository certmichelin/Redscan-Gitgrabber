/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import com.michelin.cert.redscan.utils.models.Alert;
import com.michelin.cert.redscan.utils.system.OsCommandExecutor;
import com.michelin.cert.redscan.utils.system.StreamGobbler;

import java.io.File;

import org.apache.logging.log4j.LogManager;

import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * RedScan scanner main class.
 *
 * @author Maxime ESCOURBIAC
 * @author Sylvain VAISSIER
 * @author Maxence SCHMITT
 */
@SpringBootApplication
public class ScanApplication {

  private static final File EXEC_DIR = new File("/usr/bin/gitgrabber");

  //Only required if pushing data to queues
  private final RabbitTemplate rabbitTemplate;

  @Autowired
  private DatalakeConfig datalakeConfig;

  /**
   * Constructor to init rabbit template. Only required if pushing data to queues
   *
   * @param rabbitTemplate Rabbit template.
   */
  public ScanApplication(RabbitTemplate rabbitTemplate) {
    this.rabbitTemplate = rabbitTemplate;
  }

  /**
   * RedScan Main methods.
   *
   * @param args Application arguments.
   */
  public static void main(String[] args) {
    SpringApplication.run(ScanApplication.class, args);
  }

  /**
   * Message executor.
   *
   * @param message Message received.
   */
  @RabbitListener(queues = {RabbitMqConfig.BRAND_DOMAINS})
  public void receiveMessage(String message) {
    LogManager.getLogger(ScanApplication.class).info(String.format("Start gitgrabber : %s", message));
    try {

      //Execute gitgrabber.
      OsCommandExecutor osCommandExecutor = new OsCommandExecutor();
      StreamGobbler streamGobbler = osCommandExecutor.execute(String.format("python3.7 gitGraber.py -k wordlists/keywords.txt -q %s ", message), EXEC_DIR);

      if (streamGobbler != null) {
        LogManager.getLogger(ScanApplication.class).info(String.format("Gitgrabber terminated with status : %d", streamGobbler.getExitStatus()));

        //Convert the stream output.
        if (streamGobbler.getStandardOutputs() != null) {
          if (streamGobbler.getStandardOutputs().length != 0) {
            StringBuilder sbr = new StringBuilder();
            StringBuilder sbrFull = new StringBuilder();
            for (Object object : streamGobbler.getStandardOutputs()) {
              String result = ((String) object).replaceAll("\u001B\\[[;\\d]*m", "");
              if (result.startsWith("[!]") || result.startsWith("[+]")) {
                sbr.append(result).append(System.getProperty("line.separator"));
              }
              sbrFull.append(result).append(System.getProperty("line.separator"));
            }

            LogManager.getLogger(ScanApplication.class).info(String.format("Gitgrabber output for %s : %s", message, sbrFull.toString()));

            //Update the datalake and send alert.
            datalakeConfig.upsertBrandField(message, "gitgrabber", sbr.toString());

            if (!sbr.toString().isEmpty()) {
              //Send the alert.
              Alert alert = new Alert(Alert.HIGH, String.format("[Gitgrabber] Potential leak in Github for %s", message), sbr.toString());
              rabbitTemplate.convertAndSend(RabbitMqConfig.FANOUT_ALERTS_EXCHANGE_NAME, "", alert.toJson());
            }
          }
        }

      }
    } catch (Exception ex) {
      LogManager.getLogger(ScanApplication.class).error(String.format("Exception : %s", ex.getMessage()));
    }
  }
}
