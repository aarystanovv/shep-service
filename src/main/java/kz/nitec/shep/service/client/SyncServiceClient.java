package kz.nitec.shep.service.client;

import kz.nitec.shep.service.handlers.MessageHandler;
import kz.nitec.shep.service.sync.ISyncChannel;
import kz.nitec.shep.service.sync.ISyncChannelHttpService;
import kz.nitec.shep.service.sync.RequestData;
import kz.nitec.shep.service.sync.SendMessageSendMessageFaultMsg;
import kz.nitec.shep.service.sync.SenderInfo;
import kz.nitec.shep.service.sync.SyncMessageInfo;
import kz.nitec.shep.service.sync.SyncSendMessageRequest;
import kz.nitec.shep.service.sync.SyncSendMessageResponse;
import kz.nitec.shep.service.utils.xmlds.XmlDsUtils;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class SyncServiceClient {
    private static final String SERVICE_ENDPOINT = "http://127.0.0.1:8008/shepSyncChannel";
    private ISyncChannel syncChannel;

    public SyncServiceClient() {
        ISyncChannelHttpService syncChannelService = new ISyncChannelHttpService();
        syncChannel = syncChannelService.getSyncChannelHttpPort();
        BindingProvider bp = (BindingProvider) syncChannel;
        Handler handler = new MessageHandler();
        List<Handler> handlers = new ArrayList<>();
        handlers.add(handler);
        bp.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, SERVICE_ENDPOINT);
        bp.getBinding().setHandlerChain(handlers);
    }

    public SyncSendMessageResponse sendMessage(String xml) {
        SyncSendMessageRequest request = new SyncSendMessageRequest();

        SyncMessageInfo syncMessageInfo = new SyncMessageInfo();
        syncMessageInfo.setMessageDate(XmlDsUtils.dateToCalendar(new Date()));
        syncMessageInfo.setServiceId("TEST_SERVICE_ID");
        syncMessageInfo.setMessageId(UUID.randomUUID().toString());
        SenderInfo senderInfo = new SenderInfo();
        senderInfo.setSenderId("senderId");
        senderInfo.setPassword("senderPass");
        syncMessageInfo.setSender(senderInfo);
        RequestData data = new RequestData();
        data.setData(xml);

        request.setRequestInfo(syncMessageInfo);
        request.setRequestData(data);

        try {
            SyncSendMessageResponse wsResponse = syncChannel.sendMessage(request);
            System.out.println("Sent");
            return wsResponse;
        } catch (SendMessageSendMessageFaultMsg error) {
            error.printStackTrace();
            System.out.println("SendMessageSendMessageFaultMsg: " + error.getMessage());
        }
        return null;
    }



}
