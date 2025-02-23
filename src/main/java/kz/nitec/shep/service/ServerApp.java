package kz.nitec.shep.service;

import kz.nitec.shep.service.sync.SyncServiceImpl;

import javax.xml.ws.Endpoint;

public class ServerApp {
    public static void main(String[] args) {
        Endpoint.publish("http://localhost:9980/shep-service-sync", new SyncServiceImpl());
        System.out.println("The web service is started. Go to http://localhost:9980/shep-service-sync and check it out!");
    }
}
