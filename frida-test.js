const target_func_list = {
    'NodeIKernelECDHService/init': 0xe71d84,
    'NodeIKernelECDHService/setGuid': 0xe71e9c,
    'NodeIKernelECDHService/sendSSORequest': 0xe72046,
    'NodeIKernelECDHService/sendOIDBRequest': 0xe7242e,
    'NodeIKernelECDHService/setIsDebug': 0xe727c4,
    'NodeIQQNTWrapperEngine/onSendSSOReply': 0xe72e40,
    'NodeIQQNTWrapperEngine/getECDHService': 0xe73600,
    'NodeIQQNTWrapperEngine/get': 0xe7377c,
    'NodeIKernelLoginService/get': 0xe76e54,
    'NodeIOPSafePwdEdit/get': 0xe7b6b8,
    'NodeIQQNTWrapperSession/getBatchUploadService': 0xe7cdb4,
    'NodeIQQNTWrapperSession/getFlashTransferService': 0xe7cf30,
    'NodeIQQNTWrapperSession/getVasSystemUpdateService': 0xe7d0ac,
    'NodeIQQNTWrapperSession/getQQEmailService': 0xe7d228,
    'NodeIQQNTWrapperSession/getShareToWechatService': 0xe7d3a4,
    'NodeIQQNTWrapperSession/getAlbumService': 0xe7d520,
    'NodeIQQNTWrapperSession/getTianShuService': 0xe7d69c,
    'NodeIQQNTWrapperSession/getUnitedConfigService': 0xe7d818,
    'NodeIQQNTWrapperSession/getTicketService': 0xe7d994,
    'NodeIQQNTWrapperSession/create': 0xe7db10,
    'NodeIBatchUploadManager/updateTaskInfo': 0xe8b130,
    'NodeIBatchUploadManager/suspendUploadTask': 0xe8cd78,
    'NodeIBatchUploadManager/resumeUploadTask': 0xe8cf24,
    'NodeIBatchUploadManager/cancelUploadTask': 0xe8d0d0,
    'NodeIBatchUploadManager/startUploadSession': 0xe8d27c,
    'NodeIBatchUploadManager/addTaskToSession': 0xe8d96e,
    'NodeIBatchUploadManager/cancelUploadSession': 0xe8dbb4,
    'NodeIBatchUploadManager/suspendUploadSession': 0xe8dd72,
    'NodeIBatchUploadManager/resumeUploadSession': 0xe8df30,
    'NodeIBatchUploadManager/getCachedSessions': 0xe8e0ee,
    'NodeIBatchUploadManager/deleteCachedSession': 0xe8e206,
    'NodeIKernelBatchUploadService/createBatchUploadConfig': 0xe95554,
    'NodeIKernelBatchUploadService/getBatchUploadManager': 0xe95870,
    'NodeIKernelFlashTransferService/createFlashTransferUploadTask': 0xe96d5c,
    'NodeIKernelFlashTransferService/updateFlashTransfer': 0xe97cb8,
    'NodeIKernelFlashTransferService/getFileSetList': 0xe98220,
    'NodeIKernelFlashTransferService/getFileSetListCount': 0xe986d0,
    'NodeIKernelFlashTransferService/getFileSet': 0xe98a30,
    'NodeIKernelFlashTransferService/getFileList': 0xe98f2c,
    'NodeIKernelFlashTransferService/getDownloadedFileCount': 0xe99666,
    'NodeIKernelFlashTransferService/getLocalFileList': 0xe99d0e,
    'NodeIKernelFlashTransferService/batchRemoveUserFileSetHistory': 0xe9a1c4,
    'NodeIKernelFlashTransferService/getShareLinkReq': 0xe9a6e8,
    'NodeIKernelFlashTransferService/getFileSetIdByCode': 0xe9a9fe,
    'NodeIKernelFlashTransferService/batchRemoveFile': 0xe9ad14,
    'NodeIKernelFlashTransferService/cleanFailedFiles': 0xe9b388,
    'NodeIKernelFlashTransferService/resumeAllUnfinishedTasks': 0xe9d5a6,
    'NodeIKernelFlashTransferService/addFileSetUploadListener': 0xe9d6be,
    'NodeIKernelFlashTransferService/removeFileSetUploadListener': 0xe9d908,
    'NodeIKernelFlashTransferService/startFileSetUpload': 0xe9db18,
    'NodeIKernelFlashTransferService/stopFileSetUpload': 0xe9dcc4,
    'NodeIKernelFlashTransferService/pauseFileSetUpload': 0xe9de70,
    'NodeIKernelFlashTransferService/resumeFileSetUpload': 0xe9e01c,
    'NodeIKernelFlashTransferService/pauseFileUpload': 0xe9e1c8,
    'NodeIKernelFlashTransferService/resumeFileUpload': 0xe9e374,
    'NodeIKernelFlashTransferService/stopFileUpload': 0xe9e588,
    'NodeIKernelFlashTransferService/asyncGetThumbnailPath': 0xe9e734,
    'NodeIKernelFlashTransferService/setDownLoadDefaultFileDir': 0xe9ea52,
    'NodeIKernelFlashTransferService/setFileSetDownloadDir': 0xe9ed6c,
    'NodeIKernelFlashTransferService/getFileSetDownloadDir': 0xe9f0b0,
    'NodeIKernelFlashTransferService/setFlashTransferDir': 0xe9f3ca,
    'NodeIKernelFlashTransferService/addFileSetDownloadListener': 0xe9f70e,
    'NodeIKernelFlashTransferService/removeFileSetDownloadListener': 0xe9f95c,
    'NodeIKernelFlashTransferService/startFileSetDownload': 0xe9fb6c,
    'NodeIKernelFlashTransferService/stopFileSetDownload': 0xea02d2,
    'NodeIKernelFlashTransferService/pauseFileSetDownload': 0xea06b6,
    'NodeIKernelFlashTransferService/resumeFileSetDownload': 0xea0a9a,
    'NodeIKernelFlashTransferService/startFileListDownLoad': 0xea0e7e,
    'NodeIKernelFlashTransferService/pauseFileListDownLoad': 0xea1376,
    'NodeIKernelFlashTransferService/resumeFileListDownLoad': 0xea1836,
    'NodeIKernelFlashTransferService/stopFileListDownLoad': 0xea1cf6,
    'NodeIKernelFlashTransferService/startThumbnailListDownload': 0xea21b6,
    'NodeIKernelFlashTransferService/stopThumbnailListDownload': 0xea29de,
    'NodeIKernelFlashTransferService/asyncRequestDownLoadStatus': 0xea2e4e,
    'NodeIKernelFlashTransferService/startFileTransferUrl': 0xea3168,
    'NodeIKernelFlashTransferService/addFileSetSimpleStatusListener': 0xea34c2,
    'NodeIKernelFlashTransferService/addFileSetSimpleStatusMonitoring': 0xea3778,
    'NodeIKernelFlashTransferService/removeFileSetSimpleStatusMonitoring': 0xea3a96,
    'NodeIKernelFlashTransferService/removeFileSetSimpleStatusListener': 0xea3db4,
    'NodeIKernelFlashTransferService/addDesktopFileSetSimpleStatusListener': 0xea3f60,
    'NodeIKernelFlashTransferService/addDesktopFileSetSimpleStatusMonitoring': 0xea4170,
    'NodeIKernelFlashTransferService/removeDesktopFileSetSimpleStatusMonitoring': 0xea4434,
    'NodeIKernelFlashTransferService/removeDesktopFileSetSimpleStatusListener': 0xea46f8,
    'NodeIKernelFlashTransferService/addFileSetSimpleUploadInfoListener': 0xea4908,
    'NodeIKernelFlashTransferService/addFileSetSimpleUploadInfoMonitoring': 0xea4b56,
    'NodeIKernelFlashTransferService/removeFileSetSimpleUploadInfoMonitoring': 0xea4e1a,
    'NodeIKernelFlashTransferService/removeFileSetSimpleUploadInfoListener': 0xea50de,
    'NodeIKernelFlashTransferService/sendFlashTransferMsg': 0xea52ee,
    'NodeIKernelFlashTransferService/addFlashTransferTaskInfoListener': 0xea5956,
    'NodeIKernelFlashTransferService/removeFlashTransferTaskInfoListener': 0xea5ba4,
    'NodeIKernelFlashTransferService/retrieveLocalLastFailedSetTasksInfo': 0xea5db4,
    'NodeIKernelFlashTransferService/getFailedFileList': 0xea6012,
    'NodeIKernelFlashTransferService/getLocalFileListByStatuses': 0xea6470,
    'NodeIKernelFlashTransferService/getFileSetFirstClusteringList': 0xea6ada,
    'NodeIKernelFlashTransferService/getFileSetClusteringList': 0xea6e2a,
    'NodeIKernelFlashTransferService/addFileSetClusteringListListener': 0xea71ea,
    'NodeIKernelFlashTransferService/removeFileSetClusteringListListener': 0xea7438,
    'NodeIKernelFlashTransferService/getFileSetClusteringDetail': 0xea7648,
    'NodeIKernelFlashTransferService/doAIOFlashTransferBubbleActionWithStatus': 0xea7da2,
    'NodeIKernelFlashTransferService/getFilesTransferProgress': 0xea80b4,
    'NodeIKernelFlashTransferService/pollFilesTransferProgress': 0xea87f2,
    'NodeIKernelFlashTransferService/cancelPollFilesTransferProgress': 0xea8adc,
    'NodeIKernelFlashTransferService/checkDownloadStatusBeforeLocalFileOper': 0xea909e,
    'NodeIKernelFlashTransferService/getCompressedFileFolder': 0xea9438,
    'NodeIKernelFlashTransferService/addFolderListener': 0xea9d16,
    'NodeIKernelFlashTransferService/removeFolderListener': 0xea9f64,
    'NodeIKernelFlashTransferService/addCompressedFileListener': 0xeaa174,
    'NodeIKernelFlashTransferService/removeCompressedFileListener': 0xeaa3c2,
    'NodeIKernelFlashTransferService/getFileCategoryList': 0xeaa5d2,
    'NodeIKernelFlashTransferService/addDeviceStatusListener': 0xeaab9c,
    'NodeIKernelFlashTransferService/removeDeviceStatusListener': 0xeaadea,
    'NodeIKernelFlashTransferService/checkDeviceStatus': 0xeaaffa,
    'NodeIKernelFlashTransferService/pauseAllTasks': 0xeab3fe,
    'NodeIKernelFlashTransferService/resumePausedTasksAfterDeviceStatus': 0xeab574,
    'NodeIKernelFlashTransferService/onSystemGoingToSleep': 0xeab898,
    'NodeIKernelFlashTransferService/onSystemWokeUp': 0xeab9b6,
    'NodeIKernelVasSystemUpdateService/Init': 0xeb2b14,
    'NodeIKernelVasSystemUpdateService/Destroy': 0xeb2c2c,
    'NodeIKernelVasSystemUpdateService/isExist': 0xeb2d44,
    'NodeIKernelVasSystemUpdateService/startDownload': 0xeb2f28,
    'NodeIKernelVasSystemUpdateService/getResPath': 0xeb323e,
    'NodeIQQEmailService/addKernelShareListener': 0xeb3998,
    'NodeIQQEmailService/removeKernelShareListener': 0xeb3c80,
    'NodeIQQEmailService/getEmailInfo': 0xeb3e7a,
    'NodeIQQEmailService/deleteEmail': 0xeb4240,
    'NodeIQQEmailService/markEmailNotified': 0xeb462e,
    'NodeIKernelBaseEmojiService/addKernelBaseEmojiListener': 0xeb5070,
    'NodeIKernelBaseEmojiService/removeKernelBaseEmojiListener': 0xeb5358,
    'NodeIKernelBaseEmojiService/fetchFullSysEmojis': 0xeb5552,
    'NodeIKernelBaseEmojiService/getBaseEmojiPathByIds': 0xeb5992,
    'NodeIKernelBaseEmojiService/isBaseEmojiPathExist': 0xeb6020,
    'NodeIKernelBaseEmojiService/downloadBaseEmojiByIdWithUrl': 0xeb644e,
    'NodeIKernelBaseEmojiService/downloadBaseEmojiById': 0xeb6ac4,
    'NodeIKernelEmojiService/queryAIGCEmojiEntryStatus': 0xeb8168,
    'NodeIKernelEmojiService/setAIGCEmojiEntryStatus': 0xeb83dc,
    'NodeIKernelEmojiService/getAIGCEmojiList': 0xeb8528,
    'NodeIKernelEmojiService/checkImage': 0xeb8b5c,
    'NodeIShareToWechatService/addKernelShareListener': 0xeb96d8,
    'NodeIShareToWechatService/removeKernelShareListener': 0xeb99c0,
    'NodeIShareToWechatService/isCanShareToWechat': 0xeb9bba,
    'NodeIShareToWechatService/shareMsgToWechat': 0xeb9e14,
    'NodeIKernelLockService/addKernelLockListener': 0xeba878,
    'NodeIKernelLockService/removeKernelLockListener': 0xebab60,
    'NodeIKernelLockService/unlockDesktopQQToMobile': 0xebad5a,
    'NodeIKernelLockService/lockDesktopQQ': 0xebaf76,
    'NodeIKernelGuildMsgService/setFocusSession': 0xebb720,
    'NodeIKernelGuildMsgService/getAllJoinGuildCnt': 0xebbb38,
    'NodeIKernelGuildMsgService/setGroupGuildMsgRead': 0xebbd92,
    'NodeIKernelGuildMsgService/getGuildGroupTransData': 0xebc20a,
    'NodeIKernelGuildMsgService/setGroupGuildBubbleRead': 0xebc554,
    'NodeIKernelGuildMsgService/getGuildGroupBubble': 0xebc860,
    'NodeIKernelGuildMsgService/fetchGroupGuildUnread': 0xebcbc4,
    'NodeIKernelGuildMsgService/setGroupGuildFlag': 0xebceea,
    'NodeIKernelGuildMsgService/getUnreadCntInfo': 0xebd01a,
    'NodeIKernelGuildMsgService/getGuildUnreadCntInfo': 0xebd486,
    'NodeIKernelGuildMsgService/getGuildUnreadCntTabInfo': 0xebd8b6,
    'NodeIKernelGuildMsgService/getGuildChannelListUnreadInfo': 0xebdce6,
    'NodeIKernelGuildMsgService/getAllGuildUnreadCntInfo': 0xebe116,
    'NodeIKernelGuildMsgService/getCategoryUnreadCntInfo': 0xebe332,
    'NodeIKernelGuildMsgService/getGuildFeedsUnreadCntInfo': 0xebe762,
    'NodeIKernelGuildMsgService/getAllDirectSessionUnreadCntInfo': 0xebeb92,
    'NodeIKernelGuildMsgService/clearGuildBoxAbstractReadScene': 0xebedb2,
    'NodeIKernelBdhUploadService/uploadFile': 0xebf844,
    'NodeIKernelBdhUploadService/cancelUpload': 0xec0622,
    'NodeIKernelBdhUploadService/processForTask': 0xec081c,
    'NodeIKernelAlbumService/setAlbumServiceInfo': 0xec1178,
    'NodeIKernelAlbumService/getMainPage': 0xec1402,
    'NodeIKernelAlbumService/getAlbumList': 0xec1728,
    'NodeIKernelAlbumService/getAlbumInfo': 0xec1d4e,
    'NodeIKernelAlbumService/getAllAlbumList': 0xec22e6,
    'NodeIKernelAlbumService/deleteAlbum': 0xec2776,
    'NodeIKernelAlbumService/addAlbum': 0xec2b0c,
    'NodeIKernelAlbumService/deleteMedias': 0xec45aa,
    'NodeIKernelAlbumService/modifyAlbum': 0xec4cf6,
    'NodeIKernelAlbumService/getMediaList': 0xec5166,
    'NodeIKernelAlbumService/quoteToQzone': 0xec59fa,
    'NodeIKernelAlbumService/quoteToQunAlbum': 0xec6640,
    'NodeIKernelAlbumService/queryQuoteToQunAlbumStatus': 0xec717a,
    'NodeIKernelAlbumService/getMediaListTailTab': 0xec7a7e,
    'NodeIKernelAlbumService/getQunFeeds': 0xec8016,
    'NodeIKernelAlbumService/getQunFeedDetail': 0xec8860,
    'NodeIKernelAlbumService/getQunNoticeList': 0xec94a8,
    'NodeIKernelAlbumService/getQunComment': 0xeca0b0,
    'NodeIKernelAlbumService/getQunLikes': 0xecacf8,
    'NodeIKernelAlbumService/deleteQunFeed': 0xecb170,
    'NodeIKernelAlbumService/doQunComment': 0xecb8ca,
    'NodeIKernelAlbumService/doQunReply': 0xecdd6c,
    'NodeIKernelAlbumService/doQunLike': 0xecebaa,
    'NodeIKernelAlbumService/getRedPoints': 0xecf3aa,
    'NodeIKernelAlbumService/reportViewQunFeed': 0xecf79a,
    'NodeIKernelAlbumService/getQunRight': 0xecfe10,
    'NodeIKernelAlbumService/getFeedById': 0xed0292,
    'NodeIKernelProfileLikeService/addKernelProfileLikeListener': 0xee1444,
    'NodeIKernelProfileLikeService/removeKernelProfileLikeListener': 0xee172c,
    'NodeIKernelProfileLikeService/setBuddyProfileLike': 0xee1926,
    'NodeIKernelProfileLikeService/getBuddyProfileLike': 0xee1dc6,
    'NodeIKernelProfileLikeService/getProfileLikeScidResourceInfo': 0xee244c,
    'NodeIKernelNearbyProService/addKernelNearbyProListener': 0xee4070,
    'NodeIKernelNearbyProService/removeKernelNearbyProListener': 0xee42ba,
    'NodeIKernelNearbyProService/getNearbyAllContactsUnreadCnt': 0xee44c6,
    'NodeIKernelNearbyProService/fetchNearbyProUserInfo': 0xee46e2,
    'NodeIKernelNearbyProService/setCommonExtInfo': 0xee5274,
    'NodeIKernelLiteBusinessService/addListener': 0xee5f1c,
    'NodeIKernelLiteBusinessService/removeListener': 0xee6204,
    'NodeIKernelLiteBusinessService/getLiteBusiness': 0xee63fe,
    'NodeIKernelLiteBusinessService/clearLiteBusiness': 0xee6a50,
    'NodeIKernelLiteBusinessService/getRevealTofuAuthority': 0xee6dc4,
    'NodeIKernelLiteBusinessService/insertRevealSuc': 0xee73e2,
    'NodeIKernelLiteBusinessService/recentRevealExposure': 0xee7864,
    'NodeIKernelLiteBusinessService/clearLiteActionForTesting': 0xee7a3c,
    'NodeIKernelLiteBusinessService/generateLiteActionForTesting': 0xee7c58,
    'NodeIKernelGroupSchoolService/getGroupSchoolNoticeList': 0xee8bf8,
    'NodeIKernelGroupSchoolService/getGroupSchoolNoticeDetail': 0xee9100,
    'NodeIKernelGroupSchoolService/publishGroupSchoolNotice': 0xee962c,
    'NodeIKernelGroupSchoolService/deleteGroupSchoolNotice': 0xee9e8e,
    'NodeIKernelGroupSchoolService/confirmGroupSchoolNotice': 0xeea332,
    'NodeIKernelGroupSchoolService/getGroupSchoolNoticeStatistic': 0xeea64a,
    'NodeIKernelGroupSchoolService/remindGroupSchoolNotice': 0xeeabde,
    'NodeIKernelGroupSchoolService/batchGetUserGroupSchoolRole': 0xeeb2f8,
    'NodeIKernelGroupSchoolService/getGroupSchoolTemplateList': 0xeeb7dc,
    'NodeIKernelGroupSchoolService/publishGroupSchoolTask': 0xeebb1e,
    'NodeIKernelGroupSchoolService/modifyGroupSchoolTaskStatus': 0xeec3c4,
    'NodeIKernelGroupSchoolService/getGroupSchoolTaskDetail': 0xeec8c6,
    'NodeIKernelGroupSchoolService/checkInGroupSchoolTask': 0xeecda0,
    'NodeIKernelGroupSchoolService/getGroupSchoolTaskList': 0xeed65c,
    'NodeIKernelGroupSchoolService/getGroupSchoolTaskStatistics': 0xeedaf6,
    'NodeIKernelGroupSchoolService/getGroupSchoolTaskCheckInInfo': 0xeee104,
    'NodeIKernelGroupSchoolService/getGroupSchoolTaskUnCheckInInfo': 0xeee6e2,
    'NodeIKernelGroupTabService/addListener': 0xef1a30,
    'NodeIKernelGroupTabService/removeListener': 0xef1d18,
    'NodeIKernelGroupTabService/getGroupTab': 0xef1f12,
    'NodeIKernelRobotService/fetchShareInfo': 0xef2a04,
    'NodeIKernelRobotService/resetConversation': 0xef2ea4,
    'NodeIKernelRobotService/getRobotFunctions': 0xef3310,
    'NodeIKernelRobotService/batchGetBotsMenu': 0xef3fd0,
    'NodeIKernelRobotService/fetchGroupRobotProfile': 0xef50b6,
    'NodeIKernelRobotService/getGroupRobotProfile': 0xef5826,
    'NodeIKernelRobotService/fetchGroupRobotProfileWithReq': 0xef5b32,
    'NodeIKernelRobotService/updateGroupRobotProfile': 0xef5e3e,
    'NodeIKernelRobotService/setRobotMessagePush': 0xef6028,
    'NodeIKernelRobotService/setAddRobotToGroup': 0xef6554,
    'NodeIKernelRobotService/setRemoveRobotFromGroup': 0xef69b6,
    'NodeIKernelRobotService/fetchAddRobotGroupList': 0xef6c3c,
    'NodeIKernelRobotService/addFriend': 0xef70c4,
    'NodeIKernelRobotService/removeFriend': 0xef759e,
    'NodeIKernelRobotService/robotAuth': 0xef78b6,
    'NodeIKernelRobotService/commandCallback': 0xef7c80,
    'NodeIKernelRobotService/fetchRobotShareLimit': 0xef8828,
    'NodeIKernelRobotService/sendCommonRobotToGuild': 0xef8a9a,
    'NodeIKernelRobotService/getRobotUinRange': 0xef9042,
    'NodeIKernelRobotService/fetchGroupRobotStoreDiscovery': 0xef9492,
    'NodeIKernelRobotService/sendGroupRobotStoreSearch': 0xef984a,
    'NodeIKernelRobotService/fetchGroupRobotStoreCategoryList': 0xef9f5e,
    'NodeIKernelRobotService/FetchSubscribeMsgTemplate': 0xefa468,
    'NodeIKernelRobotService/FetchSubcribeMsgTemplateStatus': 0xefaa76,
    'NodeIKernelRobotService/SubscribeMsgTemplateSet': 0xefb032,
    'NodeIKernelRobotService/fetchRecentUsedRobots': 0xefb872,
    'NodeIKernelRobotService/fetchShareArkInfo': 0xefbb86,
    'NodeIKernelRobotService/addKernelRobotListener': 0xefbee4,
    'NodeIKernelRobotService/removeKernelRobotListener': 0xefc1d0,
    'NodeIKernelRobotService/getAllRobotFriendsFromCache': 0xefc3cc,
    'NodeIKernelRobotService/fetchRecommendRobotCard': 0xefce44,
    'NodeIKernelRobotService/fetchAllRobots': 0xefd196,
    'NodeIKernelRobotService/fetchMobileRobotRecommendCards': 0xefd7a6,
    'NodeIKernelRobotService/removeAllRecommendCache': 0xefdee0,
    'NodeIKernelRobotService/setRobotPickTts': 0xefe100,
    'NodeIKernelRobotService/aiGenBotInfo': 0xefe444,
    'NodeIKernelRobotService/changeMyBot': 0xefea36,
    'NodeIKernelRobotService/fetchAiGenTemplateInfo': 0xefef00,
    'NodeIKernelRobotService/checkMyBotNum': 0xeff2d6,
    'NodeIKernelRobotService/aiGenAvatar': 0xeff4f6,
    'NodeIKernelRobotService/fetchGuildRobotPlusPanel': 0xeff922,
    'NodeIKernelRobotService/fetchGuildRobotInfo': 0xefffc0,
    'NodeIKernelRobotService/fetchRobotCommonGuild': 0xf00a14,
    'NodeIKernelRobotService/fetchGuildRobotPermission': 0xf014b0,
    'NodeIKernelRobotService/setGuildRobotPermission': 0xf01916,
    'NodeIKernelRobotService/fetchGuildRobotDirectMsgSetting': 0xf01fc4,
    'NodeIKernelRobotService/setGuildRobotDirectMsgSetting': 0xf0242a,
    'NodeIKernelRobotService/addGuildRobot': 0xf02928,
    'NodeIKernelRobotService/getAudioLiveRobotStatus': 0xf02f62,
    'NodeIKernelRobotService/subscribeGuildGlobalRobot': 0xf035c8,
    'NodeIKernelRobotService/queryGuildGlobalRobotSubscription': 0xf03aba,
    'NodeIKernelRobotService/getGuildRobotCardRecommend': 0xf03fa0,
    'NodeIKernelRobotService/getGuildRobotInlineSearch': 0xf04406,
    'NodeIKernelRobotService/upMicGuildRobot': 0xf04a88,
    'NodeIKernelRobotService/downMicGuildRobot': 0xf05390,
    'NodeIKernelRobotService/getGuildRobotList': 0xf05964,
    'NodeIKernelRobotService/FetchGroupRobotInfo': 0xf0622c,
    'NodeIO3MiscService/get': 0xf0fd48,
    'NodeIKernelOnlineStatusService/setLikeStatus': 0xf11c4c,
    'NodeIKernelOnlineStatusService/checkLikeStatus': 0xf122aa,
    'NodeIKernelOnlineStatusService/getLikeList': 0xf127ae,
    'NodeIKernelOnlineStatusService/setReadLikeList': 0xf12b0a,
    'NodeIKernelOnlineStatusService/getAggregationGroupModels': 0xf12d76,
    'NodeIKernelOnlineStatusService/didClickAggregationPageEntrance': 0xf12fd0,
    'NodeIKernelOnlineStatusService/getAggregationPageEntrance': 0xf130e8,
    'NodeIKernelOnlineStatusService/getShouldShowAIOStatusAnimation': 0xf13342,
    'NodeIKernelOnlineStatusService/addKernelOnlineStatusListener': 0xf13658,
    'NodeIKernelOnlineStatusService/removeKernelOnlineStatusListener': 0xf13940,
    'NodeIKernelOnlineStatusService/setOnlineStatusLiteBusinessSwitch': 0xf13b3a,
    'NodeIKernelTianShuService/addKernelTianShuListener': 0xf14858,
    'NodeIKernelTianShuService/removeKernelTianShuListener': 0xf14b40,
    'NodeIKernelTianShuService/requesTianShuNumeralRed': 0xf14d3a,
    'NodeIKernelTianShuService/reportTianShuNumeralRed': 0xf1526e,
    'NodeIKernelQQPlayService/init': 0xf17e98,
    'NodeIKernelQQPlayService/uninit': 0xf17fb0,
    'NodeIKernelQQPlayService/createLnkShortcut': 0xf180c8,
    'NodeIKernelQQPlayService/setForegroundWindow': 0xf183fc,
    'NodeIKernelQQPlayService/getDesktopPath': 0xf185e0,
    'NodeIKernelQQPlayService/getSimulatorProcStatus': 0xf18766,
    'NodeIKernelQQPlayService/getSystemRegValue': 0xf188b2,
    'NodeIKernelQQPlayService/startSimulator': 0xf18b78,
    'NodeIKernelQQPlayService/addKernelQQPlayListener': 0xf18d22,
    'NodeIKernelQQPlayService/sendMsg2Simulator': 0xf18f6c,
    'NodeIKernelQQPlayService/setSystemRegValue': 0xf1917e,
    'NodeIKernelUnitedConfigService/addKernelUnitedConfigListener': 0xf199e4,
    'NodeIKernelUnitedConfigService/removeKernelUnitedConfigListener': 0xf19c2e,
    'NodeIKernelUnitedConfigService/fetchUnitedCommendConfig': 0xf19e3a,
    'NodeIKernelUnitedConfigService/fetchUnitedSwitchConfig': 0xf1a0fa,
    'NodeIKernelUnitedConfigService/loadUnitedConfig': 0xf1a3ba,
    'NodeIKernelUnitedConfigService/isUnitedConfigSwitchOn': 0xf1a692,
    'NodeIKernelUnitedConfigService/registerUnitedConfigPushGroupList': 0xf1a9a8,
    'NodeIKernelWiFiPhotoHostService/addKernelWiFiPhotoHostListener': 0xf1b2bc,
    'NodeIKernelWiFiPhotoHostService/removeKernelWiFiPhotoHostListener': 0xf1b506,
    'NodeIKernelWiFiPhotoHostService/setAlbumAccessDelegate': 0xf1b712,
    'NodeIKernelWiFiPhotoHostService/precheckIfDeviceSupportWiFiPhotoRequest': 0xf1b95c,
    'NodeIKernelWiFiPhotoHostService/checkIfInFilebridge': 0xf1bbb6,
    'NodeIKernelWiFiPhotoHostService/requestVisitLocalAlbum': 0xf1bdd2,
    'NodeIKernelWiFiPhotoHostService/acceptRequest': 0xf1bfee,
    'NodeIKernelWiFiPhotoHostService/rejectRequest': 0xf1c546,
    'NodeIKernelWiFiPhotoHostService/disconnect': 0xf1c782,
    'NodeIKernelWiFiPhotoClientService/addKernelWiFiPhotoClientListener': 0xf1cef4,
    'NodeIKernelWiFiPhotoClientService/removeKernelWiFiPhotoClientListener': 0xf1d13e,
    'NodeIKernelWiFiPhotoClientService/connectToHostForTest': 0xf1d34a,
    'NodeIKernelWiFiPhotoClientService/requestVisitAlbum': 0xf1d622,
    'NodeIKernelWiFiPhotoClientService/cancelRequest': 0xf1d83e,
    'NodeIKernelWiFiPhotoClientService/requestAlbumFullAccess': 0xf1da66,
    'NodeIKernelWiFiPhotoClientService/disconnect': 0xf1dc82,
    'NodeIKernelWiFiPhotoClientService/getPeerNetworkStatus': 0xf1ddb2,
    'NodeIKernelWiFiPhotoClientService/queryUncompleteDownloadRecords': 0xf1e00c,
    'NodeIKernelWiFiPhotoClientService/resumeUncompleteDownloadRecords': 0xf1e266,
    'NodeIKernelWiFiPhotoClientService/clearUncompleteDownloadRecords': 0xf1e840,
    'NodeIKernelWiFiPhotoClientService/getAlbumList': 0xf1ea9a,
    'NodeIKernelWiFiPhotoClientService/getAlbumFileSavePath': 0xf1ecf4,
    'NodeIKernelWiFiPhotoClientService/getPhotoSimpleInfoForFirstView': 0xf1f00a,
    'NodeIKernelWiFiPhotoClientService/getAllPhotoSimpleInfo': 0xf1f330,
    'NodeIKernelWiFiPhotoClientService/getPhotoInfoBatch': 0xf1f608,
    'NodeIKernelWiFiPhotoClientService/getPhotoThumbBatchWithConfig': 0xf1fa92,
    'NodeIKernelWiFiPhotoClientService/cancelGetPhotoThumbBatch': 0xf1fd6c,
    'NodeIKernelWiFiPhotoClientService/getPhotoBatch': 0xf20030,
    'NodeIKernelWiFiPhotoClientService/cancelGetPhoto': 0xf2034e,
    'NodeIKernelWiFiPhotoClientService/cancelAll': 0xf20562,
    'NodeIKernelWiFiPhotoClientService/getPhotoAndSaveAs': 0xf20680,
    'NodeIKernelWiFiPhotoClientService/deletePhotoBatch': 0xf20a40,
    'NodeIKernelWiFiPhotoClientService/wifiPhotoPreCheck': 0xf20e72,
    'NodeIKernelWiFiPhotoClientService/getWiFiPhotoDownFileInfos': 0xf21092,
    'NodeIKernelFileBridgeHostService/addKernelFileBridgeHostListener': 0xf223e4,
    'NodeIKernelFileBridgeHostService/removeKernelFileBridgeHostListener': 0xf2262e,
    'NodeIKernelFileBridgeHostService/isLocalPasswordSet': 0xf2283a,
    'NodeIKernelFileBridgeHostService/setLocalPassword': 0xf22a94,
    'NodeIKernelFileBridgeHostService/resetLocalPassword': 0xf22d6c,
    'NodeIKernelFileBridgeHostService/isTransferingFile': 0xf22f88,
    'NodeIKernelFileBridgeHostService/disconnect': 0xf231e2,
    'NodeIKernelFileBridgeClientService/addKernelFileBridgeClientListener': 0xf26d60,
    'NodeIKernelFileBridgeClientService/removeKernelFileBridgeClientListener': 0xf26faa,
    'NodeIKernelFileBridgeClientService/preCheck': 0xf271b6,
    'NodeIKernelFileBridgeClientService/checkIfInWiFiPhotoOrFilebridge': 0xf273d2,
    'NodeIKernelFileBridgeClientService/sendRequest': 0xf275ee,
    'NodeIKernelFileBridgeClientService/authenticateWithPassword': 0xf27904,
    'NodeIKernelFileBridgeClientService/disconnect': 0xf27c8c,
    'NodeIKernelFileBridgeClientService/queryUncompleteDownloadRecords': 0xf27dbc,
    'NodeIKernelFileBridgeClientService/resumeUncompleteDownloadRecords': 0xf28016,
    'NodeIKernelFileBridgeClientService/clearUncompleteDownloadRecords': 0xf28198,
    'NodeIKernelFileBridgeClientService/getRootPageContent': 0xf28440,
    'NodeIKernelFileBridgeClientService/getPageContent': 0xf2869a,
    'NodeIKernelFileBridgeClientService/searchFolderForFiles': 0xf289c8,
    'NodeIKernelFileBridgeClientService/cancelSearchFolderForFiles': 0xf28cfe,
    'NodeIKernelFileBridgeClientService/getThumbnail': 0xf28ef8,
    'NodeIKernelFileBridgeClientService/getFile': 0xf29206,
    'NodeIKernelFileBridgeClientService/cancelGet': 0xf294e2,
    'NodeIKernelFileBridgeClientService/getFileLocalStoragePath': 0xf2968e,
    'NodeIKernelFileBridgeClientService/getCurrentStatus': 0xf299a8,
    'NodeIKernelFileBridgeClientService/getHostDeviceName': 0xf29af6,
    'NodeIKernelFileBridgeClientService/getHostSystemType': 0xf29c92,
    'NodeIKernelFileBridgeClientService/getHostIsSupportSearch': 0xf29e00,
    'NodeIKernelFileBridgeClientService/getHostMaxSearchCount': 0xf29f4e,
    'NodeIKernelFileBridgeClientService/getAuthenticationType': 0xf2a09c,
    'NodeIKernelFileBridgeClientService/getMaxAuthenticateWithoutPasswordValidDays': 0xf2a20a,
    'NodeIKernelUixConvertService/getUid': 0xf2ab70,
    'NodeIKernelUixConvertService/getUin': 0xf2b18a,
    'NodeIKernelDbToolsService/backupDatabase': 0xf2c0e0,
    'NodeIKernelDbToolsService/depositDatabase': 0xf2c3b8,
    'NodeIKernelDbToolsService/retrieveDatabase': 0xf2c690,
    'NodeIKernelTestPerformanceService/insertMsg': 0xf2cdb8,
    'NodeIKernelTestPerformanceService/execSql': 0xf30c34,
    'NodeIKernelSkinService/addKernelSkinListener': 0xf5d9f0,
    'NodeIKernelSkinService/removeKernelSkinListener': 0xf5dcd8,
    'NodeIKernelSkinService/getSystemThemeList': 0xf5ded2,
    'NodeIKernelSkinService/getSystemThemePackageList': 0xf5e12c,
    'NodeIKernelSkinService/getTemplateThemeList': 0xf5e386,
    'NodeIKernelSkinService/setTemplateCustomPrimaryColor': 0xf5e5e0,
    'NodeIKernelSkinService/setThemeInfo': 0xf5e7f4,
    'NodeIKernelSkinService/getThemeInfo': 0xf5f42a,
    'NodeIKernelSkinService/getThemeHistory': 0xf5f646,
    'NodeIKernelSkinService/previewTheme': 0xf5f8a0,
    'NodeIKernelSkinService/getThemeInfoFromImage': 0xf5fd66,
    'NodeIKernelSkinService/uploadImage': 0xf6007c,
    'NodeIKernelSkinService/getRecommendAIOColor': 0xf60392,
    'NodeIKernelSkinService/getRecommendBubbleColor': 0xf6059a,
    'NodeIKernelTicketService/addKernelTicketListener': 0xf61c14,
    'NodeIKernelTicketService/removeKernelTicketListener': 0xf61efc,
    'NodeIKernelTicketService/forceFetchClientKey': 0xf620f6,
    'NodeIKernelCollectionService/addKernelCollectionListener': 0xf62a60,
    'NodeIKernelCollectionService/removeKernelCollectionListener': 0xf62caa,
    'NodeIKernelCollectionService/getCollectionItemList': 0xf62eb6,
    'NodeIKernelCollectionService/getCollectionContent': 0xf633d4,
    'NodeIKernelCollectionService/getCollectionCustomGroupList': 0xf638e4,
    'NodeIKernelCollectionService/getCollectionUserInfo': 0xf63b3e,
    'NodeIKernelCollectionService/searchCollectionItemList': 0xf63d98,
    'NodeIKernelCollectionService/addMsgToCollection': 0xf64086,
    'NodeIKernelCollectionService/collectionArkShare': 0xf64522,
    'NodeIKernelCollectionService/collectionFileForward': 0xf64838,
    'NodeIKernelCollectionService/downloadCollectionFile': 0xf650fe,
    'NodeIKernelCollectionService/downloadCollectionFileThumbPic': 0xf661b8,
    'NodeIKernelCollectionService/downloadCollectionPic': 0xf66696,
    'NodeIKernelCollectionService/cancelDownloadCollectionFile': 0xf6755c,
    'NodeIKernelCollectionService/deleteCollectionItemList': 0xf67872,
    'NodeIKernelCollectionService/editCollectionItem': 0xf67ca0,
    'NodeIKernelCollectionService/getEditPicInfoByPath': 0xf69234,
    'NodeIKernelCollectionService/collectionFastUpload': 0xf6958e,
    'NodeIKernelCollectionService/editCollectionItemAfterFastUpload': 0xf69c6e,
    'NodeIKernelCollectionService/createNewCollectionItem': 0xf69ff8,
    'NodeISpan/end': 0xf719ec,
    'NodeISpan/addLog': 0xf71b04,
    'NodeISpan/setFailedInfo': 0xf71cae,
    'NodeISpan/setMethodName': 0xf71f12,
    'NodeISpan/addSubSpan': 0xf720bc,
    'NodeISpan/getTraceID': 0xf72446,
    'NodeQQNTWrapperUtil/getSsoCmdOfOidbReq': 0xf728c8,
    'NodeIQQNTWrapperNetwork/openNetworkService': 0xf84de0,
    'NodeIKernelGuildService/addKernelGuildListener': 0xf85d38,
    'NodeIKernelGuildService/removeKernelGuildListener': 0xf85f82,
    'NodeIKernelGuildService/preloadInitJni': 0xf8618e,
    'NodeIKernelTipOffService/addKernelTipOffListener': 0x10542b4,
    'NodeIKernelTipOffService/removeKernelTipOffListener': 0x105459c,
    'NodeIKernelTipOffService/tipOffMsgs': 0x1054796,
    'NodeIKernelTipOffService/encodeUinAesInfo': 0x1055ec8,
    'NodeIKernelTipOffService/getPskey': 0x10561c0,
    'NodeIKernelTipOffService/tipOffSendJsData': 0x1056608,
    'NodeIKernelFileAssistantService/addKernelFileAssistantListener': 0x1057a14,
    'NodeIKernelFileAssistantService/removeKernelFileAssistantListener': 0x1057cfc,
    'NodeIKernelFileAssistantService/getFileAssistantList': 0x1057ef6,
    'NodeIKernelFileAssistantService/getMoreFileAssistantList': 0x10585c4,
    'NodeIKernelFileAssistantService/downloadAllFileBySession': 0x10587ec,
    'NodeIKernelFileAssistantService/cancelAllFileActionBySession': 0x10589fe,
    'NodeIKernelFileAssistantService/getFileSessionList': 0x1058ba8,
    'NodeIKernelFileAssistantService/searchFile': 0x1058dc4,
    'NodeIKernelFileAssistantService/resetSearchFileSortType': 0x10592b8,
    'NodeIKernelFileAssistantService/searchMoreFile': 0x1059432,
    'NodeIKernelFileAssistantService/cancelSearchFile': 0x1059562,
    'NodeIKernelFileAssistantService/downloadFile': 0x105972e,
    'NodeIKernelFileAssistantService/forwardFile': 0x1059b20,
    'NodeIKernelFileAssistantService/cancelFileAction': 0x105a302,
    'NodeIKernelFileAssistantService/retryFileAction': 0x105a5da,
    'NodeIKernelFileAssistantService/deleteFile': 0x105a8b2,
    'NodeIKernelFileAssistantService/saveAs': 0x105aca8,
    'NodeIKernelFileAssistantService/saveAsWithRename': 0x105b11a,
    'NodeIKernelFileAssistantService/modifyFileInfo': 0x105b4da,
    'NodeIKernelQiDianService/addKernelQiDianListener': 0x105dde8,
    'NodeIKernelQiDianService/removeKernelQiDianListener': 0x105e0d0,
    'NodeIKernelQiDianService/requestWpaSigT': 0x105e2ca,
    'NodeIKernelQiDianService/requestQidianUidFromUin': 0x105eb00,
    'NodeIKernelQiDianService/requestExtUinForRemoteControl': 0x105ee20,
    'NodeIKernelQiDianService/requestMainUinForRemoteControl': 0x105f202,
    'NodeIKernelQiDianService/requestNaviConfig': 0x105f522,
    'NodeIKernelQiDianService/requestWpaCorpInfo': 0x105f7fc,
    'NodeIKernelQiDianService/requestWpaUserInfo': 0x105fb58,
    'NodeIKernelStorageCleanService/addKernelStorageCleanListener': 0x10607dc,
    'NodeIKernelStorageCleanService/removeKernelStorageCleanListener': 0x1060ac4,
    'NodeIKernelStorageCleanService/addCacheScanedPaths': 0x1060cbe,
    'NodeIKernelStorageCleanService/addFilesScanedPaths': 0x106124c,
    'NodeIKernelStorageCleanService/scanCache': 0x106150c,
    'NodeIKernelStorageCleanService/addReportData': 0x1061766,
    'NodeIKernelStorageCleanService/reportData': 0x1061cce,
    'NodeIKernelStorageCleanService/getChatCacheInfo': 0x1061de6,
    'NodeIKernelStorageCleanService/getFileCacheInfo': 0x10620ba,
    'NodeIKernelStorageCleanService/clearChatCacheInfo': 0x1062fd4,
    'NodeIKernelStorageCleanService/clearCacheDataByKeys': 0x10637ba,
    'NodeIKernelStorageCleanService/setSilentScan': 0x1063bac,
    'NodeIKernelStorageCleanService/closeCleanWindow': 0x1063cec,
    'NodeIKernelStorageCleanService/clearAllChatCacheInfo': 0x1063e04,
    'NodeIKernelStorageCleanService/endScan': 0x1064020,
    'NodeIKernelStorageCleanService/addNewDownloadOrUploadFile': 0x1064254,
    'NodeIKernelSettingService/addKernelSettingListener': 0x10660a8,
    'NodeIKernelSettingService/removeKernelSettingListener': 0x1066390,
    'NodeIKernelSettingService/setPrivacySetting': 0x106658a,
    'NodeIKernelSettingService/getPrivacySetting': 0x1066920,
    'NodeIKernelSettingService/getSettingForNum': 0x1066b3c,
    'NodeIKernelSettingService/getSettingForStr': 0x1066e8c,
    'NodeIKernelSettingService/getSettingForBuffer': 0x10671dc,
    'NodeIKernelSettingService/setSettingForNum': 0x106752c,
    'NodeIKernelSettingService/setSettingForStr': 0x106782a,
    'NodeIKernelSettingService/setSettingForBuffer': 0x1067b28,
    'NodeIKernelSettingService/verifyNewAccount': 0x10681b2,
    'NodeIKernelSettingService/modifyAccount': 0x106868a,
    'NodeIKernelSettingService/destroyAccount': 0x1068dfc,
    'NodeIKernelSettingService/scanCache': 0x1069018,
    'NodeIKernelSettingService/clearCache': 0x1069272,
    'NodeIKernelSettingService/getNeedConfirmSwitch': 0x10695fe,
    'NodeIKernelSettingService/setNeedConfirmSwitch': 0x106985c,
    'NodeIKernelSettingService/getSelfStartSwitch': 0x1069a9a,
    'NodeIKernelSettingService/setSelfStartSwitch': 0x1069be8,
    'NodeIKernelSettingService/getAutoLoginSwitch': 0x1069d5a,
    'NodeIKernelSettingService/setAutoLoginSwitch': 0x1069fb8,
    'NodeIKernelSettingService/getQQBrowserSwitchFromQldQQ': 0x106a1f0,
    'NodeIKernelSettingService/isQQBrowserInstall': 0x106a410,
    'NodeIKernelSettingService/openUrlWithQQBrowser': 0x106a55e,
    'NodeIKernelSettingService/openUrlInIM': 0x106a70a,
    'NodeIKernelYellowFaceForManagerService/download': 0x106b82c,
    'NodeIKernelYellowFaceForManagerService/setHistory': 0x106bc44,
    'NodeIKernelYellowFaceService/getLanguage': 0x106c2dc,
    'NodeIKernelYellowFaceService/getConfigFilePath': 0x106c536,
    'NodeIKernelYellowFaceService/update': 0x106c790,
    'NodeIKernelYellowFaceService/addListener': 0x106c9ca,
    'NodeIKernelYellowFaceService/removeListener': 0x106ccb2,
    'NodeIKernelNewFeedService/addKernelFeedListener': 0x106d5c4,
    'NodeIKernelNewFeedService/removeKernelFeedListener': 0x106d8ac,
    'NodeIKernelNewFeedService/downloadFeedRichMedia': 0x106daa6,
    'NodeIKernelNewFeedService/getFeedRichMediaFilePath': 0x106e308,
    'NodeIKernelNewFeedService/getFeedCount': 0x106e612,
    'NodeIKernelNewFeedService/delFeed': 0x106e898,
    'NodeIKernelNewFeedService/topFeedAction': 0x106efc4,
    'NodeIKernelNewFeedService/moveFeed': 0x106fcb6,
    'NodeIKernelNewFeedService/batchManageOperate': 0x1070334,
    'NodeIKernelNewFeedService/getChannelTimelineFeeds': 0x1070e1c,
    'NodeIKernelNewFeedService/getChannelRecommendFeeds': 0x1071af2,
    'NodeIKernelNewFeedService/publishFeed': 0x1071e72,
    'NodeIKernelNewFeedService/getFeedDetail': 0x1072dee,
    'NodeIKernelNewFeedService/getFeedComments': 0x10738a2,
    'NodeIKernelNewFeedService/getFeedDetailWithHotComments': 0x10747a8,
    'NodeIKernelNewFeedService/alterFeed': 0x1074b80,
    'NodeIKernelNewFeedService/doLike': 0x1075c50,
    'NodeIKernelNewFeedService/doComment': 0x1076984,
    'NodeIKernelNewFeedService/doReply': 0x10776f4,
    'NodeIKernelNewFeedService/impeach': 0x107860a,
    'NodeIKernelNewFeedService/unDoDelFeed': 0x1078fc0,
    'NodeIKernelNewFeedService/doFeedPrefer': 0x10797d6,
    'NodeIKernelNewFeedService/batchGetFeedDetail': 0x107a0fc,
    'NodeIKernelNewFeedService/getNextPageReplies': 0x107ab28,
    'NodeIKernelNewFeedService/getFeeds': 0x107b2fa,
    'NodeIKernelNewFeedService/decodeStFeed': 0x107b7ea,
    'NodeIKernelNewFeedService/encodeStFeed': 0x107d6ac,
    'NodeIKernelNewFeedService/getChannelDraft': 0x1081e78,
    'NodeIKernelNewFeedService/setChannelDraft': 0x10821a0,
    'NodeIKernelNewFeedService/getGuildFeeds': 0x10824fc,
    'NodeIKernelNewFeedService/getTopFeedConfig': 0x108316c,
    'NodeIKernelNewFeedService/getTopFeeds': 0x10833dc,
    'NodeIKernelNewFeedService/getDetailRecommendFeeds': 0x108387a,
    'NodeIKernelNewFeedService/getTopicFeeds': 0x1083e72,
    'NodeIKernelNewFeedService/searchTopic': 0x1084486,
    'NodeIKernelNewFeedService/getNotices': 0x108494c,
    'NodeIKernelNewFeedService/getFeedNotices': 0x108529a,
    'NodeIKernelFeedService/addKernelFeedListener': 0x10b6fac,
    'NodeIKernelFeedService/removeKernelFeedListener': 0x10b7256,
    'NodeIKernelFeedService/getChannelFeeds': 0x10b7450,
    'NodeIKernelFeedService/getFeedDetail': 0x10b7a5c,
    'NodeIKernelFeedService/doCommentForFeed': 0x10b82aa,
    'NodeIKernelFeedService/getChannelFeedComments': 0x10b8da2,
    'NodeIKernelFeedService/setFeedImpeach': 0x10b977e,
    'NodeIKernelFeedService/doReplyForFeed': 0x10b9b26,
    'NodeIKernelFeedService/doLike': 0x10ba302,
    'NodeIKernelFeedService/publishFeed': 0x10bb0ae,
    'NodeIKernelFeedService/alterFeed': 0x10bbad8,
    'NodeIKernelFeedService/getFeedDetailFromDB': 0x10bbe4a,
    'NodeIKernelFeedService/setFeedDetailToDB': 0x10bc122,
    'NodeIKernelFeedService/getChannelDraft': 0x10bf0ca,
    'NodeIKernelFeedService/setChannelDraft': 0x10bf3f0,
    'NodeIKernelFeedService/downloadFeedRichMedia': 0x10bf74a,
    'NodeIKernelFeedService/downloadFeedUrlFile': 0x10bf8de,
    'NodeIKernelFeedService/getFeedRichMediaFilePath': 0x10bfc86,
    'NodeIKernelFeedService/getGuildFeeds': 0x10bff94,
    'NodeIKernelRichMediaService/getVideoPlayUrl': 0x10ce90c,
    'NodeIKernelRichMediaService/getVideoPlayUrlV2': 0x10cee98,
    'NodeIKernelRichMediaService/getRichMediaFileDir': 0x10cf492,
    'NodeIKernelRichMediaService/getVideoPlayUrlInVisit': 0x10cf66a,
    'NodeIKernelRichMediaService/isFileExpired': 0x10d0374,
    'NodeIKernelAvatarService/addAvatarListener': 0x10dd874,
    'NodeIKernelAvatarService/removeAvatarListener': 0x10ddb5c,
    'NodeIKernelAvatarService/getAvatarPath': 0x10ddd56,
    'NodeIKernelAvatarService/forceDownloadAvatar': 0x10ddfb8,
    'NodeIKernelAvatarService/getGroupAvatarPath': 0x10de2ae,
    'NodeIKernelAvatarService/getConfGroupAvatarPath': 0x10de55a,
    'NodeIKernelAvatarService/forceDownloadGroupAvatar': 0x10de7e6,
    'NodeIKernelAvatarService/getGroupPortraitPath': 0x10deb20,
    'NodeIKernelAvatarService/forceDownloadGroupPortrait': 0x10dede0,
    'NodeIKernelAvatarService/getAvatarPaths': 0x10df136,
    'NodeIKernelAvatarService/getGroupAvatarPaths': 0x10df4ba,
    'NodeIKernelAvatarService/getConfGroupAvatarPaths': 0x10df802,
    'NodeIKernelAvatarService/getAvatarPathByUin': 0x10dfb2e,
    'NodeIKernelAvatarService/forceDownloadAvatarByUin': 0x10dfdda,
    'NodeIKernelRDeliveryService/getRDeliveryDataByKey': 0x10e0840,
    'NodeIKernelRDeliveryService/requestFullRemoteData': 0x10e0b70,
    'NodeIKernelRDeliveryService/requestBatchRemoteDataByScene': 0x10e0ec8,
    'NodeIKernelRDeliveryService/requestSingleRemoteDataByKey': 0x10e12f6,
    'NodeIKernelRDeliveryService/addDataChangeListener': 0x10e16c0,
    'NodeIKernelRDeliveryService/removeDataChangeListener': 0x10e19a8,
    'NodeIKernelDirectSessionService/addKernelDirectSessionListener': 0x10e25e4,
    'NodeIKernelDirectSessionService/removeKernelDirectSessionListener': 0x10e282e,
    'NodeIKernelDirectSessionService/getDirectSessionList': 0x10e2a3a,
    'NodeIKernelDirectSessionService/removeDirectSession': 0x10e2c56,
    'NodeIKernelDirectSessionService/getDirectSwitchStatus': 0x10e2f2e,
    'NodeIKernelDirectSessionService/fetchDirectSessionList': 0x10e307a,
    'NodeIKernelConfigMgrService/addKernelConfigMgrListener': 0x10e3ac0,
    'NodeIKernelConfigMgrService/removeKernelConfigMgrListener': 0x10e3da8,
    'NodeIKernelConfigMgrService/getConfigMgrInfo': 0x10e3fa2,
    'NodeIKernelConfigMgrService/getVoiceChannelMaxPeopleCount': 0x10e4206,
    'NodeIKernelConfigMgrService/getConfigMgrInfoTaskId': 0x10e4460,
    'NodeIKernelConfigMgrService/updateConfigMgrInfoTaskId': 0x10e46d8,
    'NodeIKernelConfigMgrService/saveSideBarConfig': 0x10e4914,
    'NodeIKernelConfigMgrService/loadSideBarConfig': 0x10e4d24,
    'NodeIKernelRecentContactService/addKernelRecentContactListener': 0x10e5824,
    'NodeIKernelRecentContactService/removeKernelRecentContactListener': 0x10e5b0c,
    'NodeIKernelRecentContactService/getRecentContactList': 0x10e5d06,
    'NodeIKernelRecentContactService/fetchAndSubscribeABatchOfRecentContact': 0x10e5f22,
    'NodeIKernelRecentContactService/getRecentContactListSync': 0x10e6282,
    'NodeIKernelRecentContactService/getRecentContactListSyncLimit': 0x10e66f0,
    'NodeIKernelRecentContactService/getRecentContactListSnapShot': 0x10e68b4,
    'NodeIKernelRecentContactService/getMsgUnreadCount': 0x10e6b18,
    'NodeIKernelRecentContactService/deleteRecentContacts': 0x10e6d82,
    'NodeIKernelRecentContactService/deleteRecentContactsVer2': 0x10eab10,
    'NodeIKernelRecentContactService/clearRecentContacts': 0x10eaf40,
    'NodeIKernelRecentContactService/clearRecentContactsByChatType': 0x10eb15c,
    'NodeIKernelRecentContactService/clearMsgUnreadCount': 0x10eb384,
    'NodeIKernelRecentContactService/addRecentContact': 0x10eb65c,
    'NodeIKernelRecentContactService/upsertRecentContactManually': 0x10eb968,
    'NodeIKernelRecentContactService/setGuildDisplayStatus': 0x10ecdb4,
    'NodeIKernelRecentContactService/upInsertModule': 0x10ed01a,
    'NodeIKernelRecentContactService/cleanAllModule': 0x10ed594,
    'NodeIKernelRecentContactService/jumpToSpecifyRecentContact': 0x10ed6b2,
    'NodeIKernelRecentContactService/jumpToSpecifyRecentContactVer2': 0x10edc32,
    'NodeIKernelRecentContactService/updateRecentContactExtBufForUI': 0x10ee20a,
    'NodeIKernelRecentContactService/setContactListTop': 0x10ee562,
    'NodeIKernelRecentContactService/getContacts': 0x10eec90,
    'NodeIKernelRecentContactService/updateGameMsgConfigs': 0x10ef0fe,
    'NodeIKernelRecentContactService/setAllGameMsgRead': 0x10ef74e,
    'NodeIKernelRecentContactService/getRecentContactInfos': 0x10ef96e,
    'NodeIKernelRecentContactService/getUnreadDetailsInfos': 0x10efbcc,
    'NodeIKernelRecentContactService/enterOrExitMsgList': 0x10efe2a,
    'NodeIKernelRecentContactService/getServiceAssistantRecentContactInfos': 0x10f0100,
    'NodeIKernelRecentContactService/setThirdPartyBusinessInfos': 0x10f0320,
    'NodeIKernelProfileService/addKernelProfileListener': 0x10fab6c,
    'NodeIKernelProfileService/addKernelProfileListenerForUICache': 0x10fae54,
    'NodeIKernelProfileService/removeKernelProfileListener': 0x10fb0fe,
    'NodeIKernelProfileService/prepareRegionConfig': 0x10fb2f8,
    'NodeIKernelProfileService/getLocalStrangerRemark': 0x10fb514,
    'NodeIKernelProfileService/enumCountryOptions': 0x10fb62c,
    'NodeIKernelProfileService/enumProvinceOptions': 0x10fb852,
    'NodeIKernelProfileService/enumCityOptions': 0x10fbb4a,
    'NodeIKernelProfileService/enumAreaOptions': 0x10fbec8,
    'NodeIKernelProfileService/modifySelfProfile': 0x10fc2d0,
    'NodeIKernelProfileService/modifyDesktopMiniProfile': 0x10fd136,
    'NodeIKernelProfileService/setNickName': 0x10fda68,
    'NodeIKernelProfileService/setLongNick': 0x10fdd40,
    'NodeIKernelProfileService/setBirthday': 0x10fe018,
    'NodeIKernelProfileService/setGander': 0x10fe27e,
    'NodeIKernelProfileService/setHeader': 0x10fe4a6,
    'NodeIKernelProfileService/setRecommendImgFlag': 0x10fe782,
    'NodeIKernelProfileService/getUserSimpleInfo': 0x10fe9ae,
    'NodeIKernelProfileService/getUserDetailInfo': 0x10fedb2,
    'NodeIKernelProfileService/getUserDetailInfoWithBizInfo': 0x10ff08e,
    'NodeIKernelProfileService/getUserDetailInfoByUin': 0x10ff436,
    'NodeIKernelProfileService/getZplanAvatarInfos': 0x10ff794,
    'NodeIKernelProfileService/getStatus': 0x10ffbc6,
    'NodeIKernelProfileService/startStatusPolling': 0x10ffea2,
    'NodeIKernelProfileService/getSelfStatus': 0x10fffe4,
    'NodeIKernelProfileService/setdisableEmojiShortCuts': 0x1100204,
    'NodeIKernelProfileService/getProfileQzonePicInfo': 0x1100430,
    'NodeIKernelProfileService/getCoreInfo': 0x1100778,
    'NodeIKernelProfileService/getCoreAndBaseInfo': 0x1100b34,
    'NodeIKernelProfileService/getStatusInfo': 0x1100ef0,
    'NodeIKernelProfileService/getRelationFlag': 0x11012ac,
    'NodeIKernelProfileService/getOtherFlag': 0x1101668,
    'NodeIKernelProfileService/getVasInfo': 0x1101a24,
    'NodeIKernelProfileService/getIntimate': 0x1101de0,
    'NodeIKernelProfileService/getStockLocalData': 0x110219c,
    'NodeIKernelProfileService/updateStockLocalData': 0x1102558,
    'NodeIKernelProfileService/updateProfileData': 0x1102e1e,
    'NodeIKernelProfileService/getUinByUid': 0x110313c,
    'NodeIKernelProfileService/getUidByUin': 0x11034f8,
    'NodeIKernelProfileService/fetchUserDetailInfo': 0x1103874,
    'NodeIKernelPublicAccountService/addListener': 0x1111f90,
    'NodeIKernelPublicAccountService/removeListener': 0x1112278,
    'NodeIKernelPublicAccountService/getFollowList': 0x1112472,
    'NodeIKernelPublicAccountService/follow': 0x11126cc,
    'NodeIKernelPublicAccountService/unfollow': 0x1112a82,
    'NodeIKernelMsgService/addKernelMsgListener': 0x11133f4,
    'NodeIKernelMsgService/addKernelMsgImportToolListener': 0x11136dc,
    'NodeIKernelMsgService/removeKernelMsgListener': 0x11139c4,
    'NodeIKernelMsgService/addKernelTempChatSigListener': 0x1113bbe,
    'NodeIKernelMsgService/removeKernelTempChatSigListener': 0x1113ea6,
    'NodeIKernelMsgService/setAutoReplyTextList': 0x11140a0,
    'NodeIKernelMsgService/getAutoReplyTextList': 0x1114684,
    'NodeIKernelMsgService/getOnLineDev': 0x11148de,
    'NodeIKernelMsgService/kickOffLine': 0x1114afa,
    'NodeIKernelMsgService/setStatus': 0x1114f38,
    'NodeIKernelMsgService/fetchStatusMgrInfo': 0x111542e,
    'NodeIKernelMsgService/fetchStatusUnitedConfigInfo': 0x1115688,
    'NodeIKernelMsgService/getOnlineStatusSmallIconBasePath': 0x11158a4,
    'NodeIKernelMsgService/getOnlineStatusSmallIconFileNameByUrl': 0x1115ac0,
    'NodeIKernelMsgService/downloadOnlineStatusSmallIconByUrl': 0x1115d98,
    'NodeIKernelMsgService/getOnlineStatusBigIconBasePath': 0x1115f50,
    'NodeIKernelMsgService/downloadOnlineStatusBigIconByUrl': 0x1116170,
    'NodeIKernelMsgService/getOnlineStatusCommonPath': 0x111632a,
    'NodeIKernelMsgService/getOnlineStatusCommonFileNameByUrl': 0x1116606,
    'NodeIKernelMsgService/downloadOnlineStatusCommonByUrl': 0x11168e2,
    'NodeIKernelMsgService/setToken': 0x1116c64,
    'NodeIKernelMsgService/switchForeGround': 0x11173f0,
    'NodeIKernelMsgService/switchBackGround': 0x1117610,
    'NodeIKernelMsgService/setTokenForMqq': 0x1117bbc,
    'NodeIKernelMsgService/switchForeGroundForMqq': 0x1117e68,
    'NodeIKernelMsgService/switchBackGroundForMqq': 0x1118114,
    'NodeIKernelMsgService/getMsgSetting': 0x11183c0,
    'NodeIKernelMsgService/setMsgSetting': 0x11185e0,
    'NodeIKernelMsgService/sendMsg': 0x1118e08,
    'NodeIKernelMsgService/addSendMsg': 0x11199ba,
    'NodeIKernelMsgService/cancelSendMsg': 0x1119f10,
    'NodeIKernelMsgService/switchToOfflineSendMsg': 0x111a1ac,
    'NodeIKernelMsgService/reqToOfflineSendMsg': 0x111a448,
    'NodeIKernelMsgService/refuseReceiveOnlineFileMsg': 0x111a80a,
    'NodeIKernelMsgService/resendMsg': 0x111abcc,
    'NodeIKernelMsgService/stopGenerateMsg': 0x111af8e,
    'NodeIKernelMsgService/regenerateMsg': 0x111b350,
    'NodeIKernelMsgService/recallMsg': 0x111b712,
    'NodeIKernelMsgService/recallMsgs': 0x111bb74,
    'NodeIKernelMsgService/reeditRecallMsg': 0x111c356,
    'NodeIKernelMsgService/forwardMsg': 0x111c718,
    'NodeIKernelMsgService/forwardMsgWithComment': 0x111cee6,
    'NodeIKernelMsgService/forwardSubMsgWithComment': 0x111d852,
    'NodeIKernelMsgService/forwardRichMsgInVist': 0x111e3ba,
    'NodeIKernelMsgService/forwardFile': 0x111f5aa,
    'NodeIKernelMsgService/multiForwardMsg': 0x111fc3c,
    'NodeIKernelMsgService/multiForwardMsgWithComment': 0x1120432,
    'NodeIKernelMsgService/buildMultiForwardMsg': 0x1120c64,
    'NodeIKernelMsgService/deleteRecallMsg': 0x1120fba,
    'NodeIKernelMsgService/deleteRecallMsgForLocal': 0x112137c,
    'NodeIKernelMsgService/addLocalGrayTipMsg': 0x112173e,
    'NodeIKernelMsgService/addLocalJsonGrayTipMsg': 0x1121b4e,
    'NodeIKernelMsgService/addLocalJsonGrayTipMsgExt': 0x1122038,
    'NodeIKernelMsgService/IsLocalJsonTipValid': 0x1122960,
    'NodeIKernelMsgService/addLocalAVRecordMsg': 0x1122ac2,
    'NodeIKernelMsgService/addLocalTofuRecordMsg': 0x1123512,
    'NodeIKernelMsgService/addLocalRecordMsg': 0x11238ec,
    'NodeIKernelMsgService/addLocalRecordMsgWithExtInfos': 0x1123e82,
    'NodeIKernelMsgService/deleteMsg': 0x11247e4,
    'NodeIKernelMsgService/updateElementExtBufForUI': 0x1124c46,
    'NodeIKernelMsgService/updateMsgRecordExtPbBufForUI': 0x112516e,
    'NodeIKernelMsgService/startMsgSync': 0x11255ae,
    'NodeIKernelMsgService/startGuildMsgSync': 0x11256cc,
    'NodeIKernelMsgService/isGuildChannelSync': 0x11257ea,
    'NodeIKernelMsgService/generateMsgUniqueId': 0x1125e8c,
    'NodeIKernelMsgService/isMsgMatched': 0x1126126,
    'NodeIKernelMsgService/getOnlineFileMsgs': 0x1126434,
    'NodeIKernelMsgService/getAllOnlineFileMsgs': 0x1126780,
    'NodeIKernelMsgService/getLatestDbMsgs': 0x11269a0,
    'NodeIKernelMsgService/getLastMessageList': 0x1126cc0,
    'NodeIKernelMsgService/getAioFirstViewLatestMsgs': 0x11270f2,
    'NodeIKernelMsgService/getMsgs': 0x112744e,
    'NodeIKernelMsgService/getMsgsIncludeSelf': 0x112786a,
    'NodeIKernelMsgService/getMsgsWithMsgTimeAndClientSeqForC2C': 0x1127c86,
    'NodeIKernelMsgService/getMsgsWithStatus': 0x1128210,
    'NodeIKernelMsgService/getMsgsBySeqRange': 0x1128ac6,
    'NodeIKernelMsgService/getMsgsBySeqAndCount': 0x1128f82,
    'NodeIKernelMsgService/getMsgsByMsgId': 0x11293f0,
    'NodeIKernelMsgService/getRecallMsgsByMsgId': 0x1129852,
    'NodeIKernelMsgService/getMsgsBySeqList': 0x1129cb4,
    'NodeIKernelMsgService/getMsgsExt': 0x112a116,
    'NodeIKernelMsgService/getSingleMsg': 0x112ac0a,
    'NodeIKernelMsgService/getSourceOfReplyMsg': 0x112afcc,
    'NodeIKernelMsgService/getSourceOfReplyMsgV2': 0x112b488,
    'NodeIKernelMsgService/getMsgByClientSeqAndTime': 0x112b944,
    'NodeIKernelMsgService/getSourceOfReplyMsgByClientSeqAndTime': 0x112be00,
    'NodeIKernelMsgService/getMsgsByTypeFilter': 0x112c398,
    'NodeIKernelMsgService/getMsgsByTypeFilters': 0x112cb1a,
    'NodeIKernelMsgService/getMsgWithAbstractByFilterParam': 0x112d138,
    'NodeIKernelMsgService/queryMsgsWithFilter': 0x112da78,
    'NodeIKernelMsgService/queryMsgsWithFilterVer2': 0x112e748,
    'NodeIKernelMsgService/queryMsgsWithFilterEx': 0x112ec48,
    'NodeIKernelMsgService/queryFileMsgsDesktop': 0x112f1e2,
    'NodeIKernelMsgService/queryFileDownloadList': 0x112f77c,
    'NodeIKernelMsgService/queryMoreFileDownloadList': 0x112fa72,
    'NodeIKernelMsgService/setMsgRichInfoFlag': 0x112fd4e,
    'NodeIKernelMsgService/queryPicOrVideoMsgs': 0x112fe90,
    'NodeIKernelMsgService/queryPicOrVideoMsgsDesktop': 0x113042a,
    'NodeIKernelMsgService/queryEmoticonMsgs': 0x1130b30,
    'NodeIKernelMsgService/queryTroopEmoticonMsgs': 0x11310ca,
    'NodeIKernelMsgService/queryMsgsAndAbstractsWithFilter': 0x1131664,
    'NodeIKernelMsgService/setFocusOnGuild': 0x1131c3a,
    'NodeIKernelMsgService/setFocusSession': 0x1131d7c,
    'NodeIKernelMsgService/enableFilterUnreadInfoNotify': 0x1131f8a,
    'NodeIKernelMsgService/enableFilterMsgAbstractNotify': 0x11320cc,
    'NodeIKernelMsgService/onScenesChangeForSilenceMode': 0x113220e,
    'NodeIKernelMsgService/getContactUnreadCnt': 0x1132340,
    'NodeIKernelMsgService/getUnreadCntInfo': 0x1132772,
    'NodeIKernelMsgService/getGuildUnreadCntInfo': 0x1132ba4,
    'NodeIKernelMsgService/getGuildUnreadCntTabInfo': 0x1132fd6,
    'NodeIKernelMsgService/getGuildChannelListUnreadInfo': 0x1133408,
    'NodeIKernelMsgService/getAllGuildUnreadCntInfo': 0x113383a,
    'NodeIKernelMsgService/getAllJoinGuildCnt': 0x1133a5a,
    'NodeIKernelMsgService/getAllDirectSessionUnreadCntInfo': 0x1133c7a,
    'NodeIKernelMsgService/getCategoryUnreadCntInfo': 0x1133e9a,
    'NodeIKernelMsgService/getGuildFeedsUnreadCntInfo': 0x11342cc,
    'NodeIKernelMsgService/setUnVisibleChannelCntInfo': 0x11346fe,
    'NodeIKernelMsgService/setUnVisibleChannelTypeCntInfo': 0x1134b30,
    'NodeIKernelMsgService/setVisibleGuildCntInfo': 0x1134fd4,
    'NodeIKernelMsgService/setMsgRead': 0x11352b0,
    'NodeIKernelMsgService/setAllC2CAndGroupMsgRead': 0x11355be,
    'NodeIKernelMsgService/setGuildMsgRead': 0x11357de,
    'NodeIKernelMsgService/setAllGuildMsgRead': 0x1135aba,
    'NodeIKernelMsgService/setAllDirectMsgRead': 0x1135cda,
    'NodeIKernelMsgService/setMsgReadAndReport': 0x1135efa,
    'NodeIKernelMsgService/setSpecificMsgReadAndReport': 0x113a574,
    'NodeIKernelMsgService/setLocalMsgRead': 0x113a936,
    'NodeIKernelMsgService/setGroupGuildMsgRead': 0x113ac44,
    'NodeIKernelMsgService/getGuildGroupTransData': 0x113b0c0,
    'NodeIKernelMsgService/setGroupGuildBubbleRead': 0x113b3ce,
    'NodeIKernelMsgService/getGuildGroupBubble': 0x113b6dc,
    'NodeIKernelMsgService/fetchGroupGuildUnread': 0x113ba04,
    'NodeIKernelMsgService/setGroupGuildFlag': 0x113bd2c,
    'NodeIKernelMsgService/setGuildUDCFlag': 0x113be5e,
    'NodeIKernelMsgService/setGuildTabUserFlag': 0x113bf90,
    'NodeIKernelMsgService/setBuildMode': 0x113c0c2,
    'NodeIKernelMsgService/setConfigurationServiceData': 0x113c1f4,
    'NodeIKernelMsgService/setMarkUnreadFlag': 0x113c75e,
    'NodeIKernelMsgService/getChannelEventFlow': 0x113c958,
    'NodeIKernelMsgService/getMsgEventFlow': 0x113cb34,
    'NodeIKernelMsgService/getRichMediaFilePathForMobileQQSend': 0x113cd10,
    'NodeIKernelMsgService/getRichMediaFilePathForGuild': 0x113d55a,
    'NodeIKernelMsgService/assembleMobileQQRichMediaFilePath': 0x113d772,
    'NodeIKernelMsgService/getFileThumbSavePathForSend': 0x113d98a,
    'NodeIKernelMsgService/getFileThumbSavePath': 0x113db44,
    'NodeIKernelMsgService/copyFileWithDelExifInfo': 0x113ddba,
    'NodeIKernelMsgService/translatePtt2Text': 0x113e0e2,
    'NodeIKernelMsgService/setPttPlayedState': 0x113e59e,
    'NodeIKernelMsgService/getArkMsgConfig': 0x113ea5a,
    'NodeIKernelMsgService/getArkToMarkdownMsgTemplate': 0x113efbc,
    'NodeIKernelMsgService/fetchFavEmojiList': 0x113f248,
    'NodeIKernelMsgService/addFavEmoji': 0x113f5ba,
    'NodeIKernelMsgService/fetchMarketEmoticonList': 0x113ff8e,
    'NodeIKernelMsgService/delMarketEmojiTab': 0x114020e,
    'NodeIKernelMsgService/fetchBottomEmojiTableList': 0x11407ca,
    'NodeIKernelMsgService/moveBottomEmojiTable': 0x1140c3e,
    'NodeIKernelMsgService/modifyBottomEmojiTableSwitchStatus': 0x11413dc,
    'NodeIKernelMsgService/fetchMarketEmoticonShowImage': 0x1141a28,
    'NodeIKernelMsgService/fetchMarketEmoticonAioImage': 0x1141f84,
    'NodeIKernelMsgService/fetchMarketEmotionJsonFile': 0x1142666,
    'NodeIKernelMsgService/getMarketEmoticonPath': 0x1142892,
    'NodeIKernelMsgService/getMarketEmoticonPathBySync': 0x1142d16,
    'NodeIKernelMsgService/fetchMarketEmoticonFaceImages': 0x11430cc,
    'NodeIKernelMsgService/fetchMarketEmoticonAuthDetail': 0x11433c4,
    'NodeIKernelMsgService/getFavMarketEmoticonInfo': 0x114380e,
    'NodeIKernelMsgService/addRecentUsedFace': 0x1143b38,
    'NodeIKernelMsgService/getRecentUsedFaceList': 0x1143f82,
    'NodeIKernelMsgService/getMarketEmoticonEncryptKeys': 0x11441ea,
    'NodeIKernelMsgService/downloadEmojiPic': 0x1144642,
    'NodeIKernelMsgService/deleteFavEmoji': 0x1144d38,
    'NodeIKernelMsgService/modifyFavEmojiDesc': 0x114512e,
    'NodeIKernelMsgService/queryFavEmojiByDesc': 0x11458d2,
    'NodeIKernelMsgService/getHotPicInfoListSearchString': 0x1145bae,
    'NodeIKernelMsgService/getHotPicSearchResult': 0x1145f7c,
    'NodeIKernelMsgService/getHotPicHotWords': 0x1146d90,
    'NodeIKernelMsgService/getHotPicJumpInfo': 0x1147986,
    'NodeIKernelMsgService/getEmojiResourcePath': 0x1147de4,
    'NodeIKernelMsgService/JoinDragonGroupEmoji': 0x114804c,
    'NodeIKernelMsgService/getMsgAbstracts': 0x1148800,
    'NodeIKernelMsgService/getMsgAbstract': 0x1148c8a,
    'NodeIKernelMsgService/getMsgAbstractList': 0x114904c,
    'NodeIKernelMsgService/getMsgAbstractListBySeqRange': 0x11494ae,
    'NodeIKernelMsgService/refreshMsgAbstracts': 0x114996a,
    'NodeIKernelMsgService/refreshMsgAbstractsByGuildIds': 0x1149c88,
    'NodeIKernelMsgService/getRichMediaElement': 0x1149f4c,
    'NodeIKernelMsgService/cancelGetRichMediaElement': 0x114a7d4,
    'NodeIKernelMsgService/refuseGetRichMediaElement': 0x114a9b2,
    'NodeIKernelMsgService/switchToOfflineGetRichMediaElement': 0x114ab90,
    'NodeIKernelMsgService/downloadRichMedia': 0x114ad6e,
    'NodeIKernelMsgService/getFirstUnreadMsgSeq': 0x114af4c,
    'NodeIKernelMsgService/getFirstUnreadCommonMsg': 0x114b298,
    'NodeIKernelMsgService/getFirstUnreadAtmeMsg': 0x114b5e4,
    'NodeIKernelMsgService/getFirstUnreadAtallMsg': 0x114b8f2,
    'NodeIKernelMsgService/getNavigateInfo': 0x114bc00,
    'NodeIKernelMsgService/getChannelFreqLimitInfo': 0x114bf4c,
    'NodeIKernelMsgService/getRecentUseEmojiList': 0x114c128,
    'NodeIKernelMsgService/getRecentEmojiList': 0x114c386,
    'NodeIKernelMsgService/setMsgEmojiLikes': 0x114c5b2,
    'NodeIKernelMsgService/getMsgEmojiLikesList': 0x114cb78,
    'NodeIKernelMsgService/setMsgEmojiLikesForRole': 0x114d1ee,
    'NodeIKernelMsgService/clickInlineKeyboardButton': 0x114d996,
    'NodeIKernelMsgService/setCurOnScreenMsg': 0x114e324,
    'NodeIKernelMsgService/setCurOnScreenMsgForMsgEvent': 0x114e674,
    'NodeIKernelMsgService/getMiscData': 0x114ec84,
    'NodeIKernelMsgService/setMiscData': 0x114ef9e,
    'NodeIKernelMsgService/getBookmarkData': 0x114f320,
    'NodeIKernelMsgService/setBookmarkData': 0x114f63a,
    'NodeIKernelMsgService/sendShowInputStatusReq': 0x114f97e,
    'NodeIKernelMsgService/queryCalendar': 0x114fc82,
    'NodeIKernelMsgService/queryFirstMsgSeq': 0x1150082,
    'NodeIKernelMsgService/queryRoamCalendar': 0x1150482,
    'NodeIKernelMsgService/queryFirstRoamMsg': 0x1150844,
    'NodeIKernelMsgService/fetchLongMsg': 0x1150c44,
    'NodeIKernelMsgService/fetchLongMsgWithCb': 0x1150ee0,
    'NodeIKernelMsgService/setIsStopKernelFetchLongMsg': 0x11512a2,
    'NodeIKernelMsgService/insertGameResultAsMsgToDb': 0x11514da,
    'NodeIKernelMsgService/getMultiMsg': 0x11517f8,
    'NodeIKernelMsgService/setDraft': 0x1151cf0,
    'NodeIKernelMsgService/getDraft': 0x11521f6,
    'NodeIKernelMsgService/deleteDraft': 0x1152542,
    'NodeIKernelMsgService/getRecentHiddenSesionList': 0x1152850,
    'NodeIKernelMsgService/setRecentHiddenSession': 0x1152aae,
    'NodeIKernelMsgService/delRecentHiddenSession': 0x11533f2,
    'NodeIKernelMsgService/getCurHiddenSession': 0x115382a,
    'NodeIKernelMsgService/setCurHiddenSession': 0x1153a4a,
    'NodeIKernelMsgService/setReplyDraft': 0x1153d58,
    'NodeIKernelMsgService/getReplyDraft': 0x115437e,
    'NodeIKernelMsgService/deleteReplyDraft': 0x1154740,
    'NodeIKernelMsgService/getFirstUnreadAtMsg': 0x1154b02,
    'NodeIKernelMsgService/clearMsgRecords': 0x1154e4e,
    'NodeIKernelMsgService/IsExistOldDb': 0x115519a,
    'NodeIKernelMsgService/canImportOldDbMsg': 0x11552e8,
    'NodeIKernelMsgService/getOldMsgDbInfo': 0x1155546,
    'NodeIKernelMsgService/stopImportOldDbMsg': 0x11557a4,
    'NodeIKernelMsgService/setPowerStatus': 0x11559c4,
    'NodeIKernelMsgService/canProcessDataMigration': 0x1155b06,
    'NodeIKernelMsgService/importOldDbMsg': 0x1155d26,
    'NodeIKernelMsgService/stopImportOldDbMsgAndroid': 0x1155f46,
    'NodeIKernelMsgService/isMqqDataImportFinished': 0x1156064,
    'NodeIKernelMsgService/getMqqDataImportTableNames': 0x1156284,
    'NodeIKernelMsgService/getCurChatImportStatusByUin': 0x11564e2,
    'NodeIKernelMsgService/getDataImportUserLevel': 0x1156724,
    'NodeIKernelMsgService/importDataLineMsg': 0x1156872,
    'NodeIKernelMsgService/getMsgQRCode': 0x1156990,
    'NodeIKernelMsgService/getGuestMsgAbstracts': 0x1156bee,
    'NodeIKernelMsgService/getGuestMsgByRange': 0x115708c,
    'NodeIKernelMsgService/getGuestMsgAbstractByRange': 0x11574f8,
    'NodeIKernelMsgService/registerSysMsgNotification': 0x1157926,
    'NodeIKernelMsgService/unregisterSysMsgNotification': 0x1157dd2,
    'NodeIKernelMsgService/sendSsoCmdReqByContend': 0x115827e,
    'NodeIKernelMsgService/enterOrExitAio': 0x1158600,
    'NodeIKernelMsgService/prepareTempChat': 0x1158bd0,
    'NodeIKernelMsgService/getTempChatInfo': 0x1159776,
    'NodeIKernelMsgService/setContactLocalTop': 0x1159aa0,
    'NodeIKernelMsgService/switchAnonymousChat': 0x1159dc8,
    'NodeIKernelMsgService/renameAnonyChatNick': 0x115a0fa,
    'NodeIKernelMsgService/getAnonymousInfo': 0x115a414,
    'NodeIKernelMsgService/updateAnonymousInfo': 0x115a808,
    'NodeIKernelMsgService/sendSummonMsg': 0x115aeaa,
    'NodeIKernelMsgService/outputGuildUnreadInfo': 0x115b484,
    'NodeIKernelMsgService/checkMsgWithUrl': 0x115b660,
    'NodeIKernelMsgService/checkTabListStatus': 0x115bb50,
    'NodeIKernelMsgService/getABatchOfContactMsgBoxInfo': 0x115bd70,
    'NodeIKernelMsgService/insertMsgToMsgBox': 0x115c1de,
    'NodeIKernelMsgService/isHitEmojiKeyword': 0x115c5d4,
    'NodeIKernelMsgService/getKeyWordRelatedEmoji': 0x115cc5c,
    'NodeIKernelMsgService/recordEmoji': 0x115d1ec,
    'NodeIKernelMsgService/fetchGetHitEmotionsByWord': 0x115d916,
    'NodeIKernelMsgService/deleteAllRoamMsgs': 0x115dc94,
    'NodeIKernelMsgService/packRedBag': 0x115df80,
    'NodeIKernelMsgService/grabRedBag': 0x115e962,
    'NodeIKernelMsgService/pullDetail': 0x115f43a,
    'NodeIKernelMsgService/selectPasswordRedBag': 0x115f996,
    'NodeIKernelMsgService/pullRedBagPasswordList': 0x115fb1e,
    'NodeIKernelMsgService/requestTianshuAdv': 0x115fd7c,
    'NodeIKernelMsgService/tianshuReport': 0x11603ce,
    'NodeIKernelMsgService/tianshuMultiReport': 0x1160c52,
    'NodeIKernelMsgService/GetMsgSubType': 0x11610e2,
    'NodeIKernelMsgService/setIKernelPublicAccountAdapter': 0x11612ec,
    'NodeIKernelMsgService/createUidFromTinyId': 0x116153a,
    'NodeIKernelMsgService/dataMigrationGetDataAvaiableContactList': 0x1161872,
    'NodeIKernelMsgService/dataMigrationGetMsgList': 0x1161ad0,
    'NodeIKernelMsgService/dataMigrationStopOperation': 0x1161e40,
    'NodeIKernelMsgService/dataMigrationImportMsgPbRecord': 0x116203c,
    'NodeIKernelMsgService/dataMigrationGetResourceLocalDestinyPath': 0x1163394,
    'NodeIKernelMsgService/dataMigrationSetIOSPathPrefix': 0x116360e,
    'NodeIKernelMsgService/getServiceAssistantSwitch': 0x11637ba,
    'NodeIKernelMsgService/setServiceAssistantSwitch': 0x1163c54,
    'NodeIKernelMsgService/setSubscribeFolderUsingSmallRedPoint': 0x1164252,
    'NodeIKernelMsgService/clearGuildNoticeRedPoint': 0x1164394,
    'NodeIKernelMsgService/clearFeedNoticeRedPoint': 0x116474c,
    'NodeIKernelMsgService/clearFeedSquareRead': 0x1164b04,
    'NodeIKernelMsgService/clearGuildVoiceChannelRedPoint': 0x1164ee8,
    'NodeIKernelMsgService/IsC2CStyleChatType': 0x11652a0,
    'NodeIKernelMsgService/IsTempChatType': 0x1165402,
    'NodeIKernelMsgService/getGuildInteractiveNotification': 0x1165564,
    'NodeIKernelMsgService/getGuildNotificationAbstract': 0x116588c,
    'NodeIKernelMsgService/setFocusOnBase': 0x1165ba6,
    'NodeIKernelMsgService/queryArkInfo': 0x1165d82,
    'NodeIKernelMsgService/queryUserSecQuality': 0x11662e4,
    'NodeIKernelMsgService/getGuildMsgAbFlag': 0x1166542,
    'NodeIKernelMsgService/getGroupMsgStorageTime': 0x11667a0,
    'NodeIKernelMsgService/likeOrDislikeReportForMsg': 0x1166926,
    'NodeIKernelMsgService/feedBackReportForMsg': 0x11671e0,
    'NodeIKernelGroupService/addKernelGroupListener': 0x117a9d4,
    'NodeIKernelGroupService/removeKernelGroupListener': 0x117acbc,
    'NodeIKernelGroupService/getAllMemberList': 0x117aeb6,
    'NodeIKernelGroupService/getMemberCommonInfo': 0x117b228,
    'NodeIKernelGroupService/getMemberExtInfo': 0x117c062,
    'NodeIKernelGroupService/getMemberInfoForMqq': 0x117cda6,
    'NodeIKernelGroupService/createMemberListScene': 0x117d2b0,
    'NodeIKernelGroupService/destroyMemberListScene': 0x117d5a8,
    'NodeIKernelGroupService/getNextMemberList': 0x117d752,
    'NodeIKernelGroupService/getPrevMemberList': 0x117dc28,
    'NodeIKernelGroupService/monitorMemberList': 0x117df88,
    'NodeIKernelGroupService/searchMember': 0x117e216,
    'NodeIKernelGroupService/getMemberInfo': 0x117e556,
    'NodeIKernelGroupService/getMemberInfoCache': 0x117ea60,
    'NodeIKernelGroupService/kickMember': 0x117ee26,
    'NodeIKernelGroupService/kickMemberV2': 0x117f412,
    'NodeIKernelGroupService/modifyMemberRole': 0x117fde2,
    'NodeIKernelGroupService/modifyMemberCardName': 0x1180196,
    'NodeIKernelGroupService/getTransferableMemberInfo': 0x1180598,
    'NodeIKernelGroupService/transferGroup': 0x11808f6,
    'NodeIKernelGroupService/transferGroupV2': 0x1180cf8,
    'NodeIKernelGroupService/getGroupList': 0x1181138,
    'NodeIKernelGroupService/getGroupExtList': 0x1181370,
    'NodeIKernelGroupService/getGroupExt0xEF0Info': 0x11815a8,
    'NodeIKernelGroupService/getGroupDetailInfo': 0x118233e,
    'NodeIKernelGroupService/getGroupAllInfo': 0x118267c,
    'NodeIKernelGroupService/getGroupDetailInfoForMqq': 0x11829ba,
    'NodeIKernelGroupService/getGroupDetailInfoByFilter': 0x1182d22,
    'NodeIKernelGroupService/getDiscussExistInfo': 0x11835ac,
    'NodeIKernelGroupService/getGroupConfMember': 0x118390a,
    'NodeIKernelGroupService/getGroupMsgMask': 0x1183c42,
    'NodeIKernelGroupService/getGroupPortrait': 0x1183e62,
    'NodeIKernelGroupService/modifyGroupName': 0x1184184,
    'NodeIKernelGroupService/modifyGroupRemark': 0x1184530,
    'NodeIKernelGroupService/modifyGroupDetailInfo': 0x11848bc,
    'NodeIKernelGroupService/modifyGroupDetailInfoV2': 0x1186daa,
    'NodeIKernelGroupService/setGroupMsgMask': 0x118765c,
    'NodeIKernelGroupService/setGroupMsgMaskV2': 0x118799a,
    'NodeIKernelGroupService/changeGroupShieldSettingTemp': 0x1187e88,
    'NodeIKernelGroupService/inviteToGroup': 0x11881c0,
    'NodeIKernelGroupService/inviteToGroupV2': 0x118868c,
    'NodeIKernelGroupService/inviteMembersToGroup': 0x1189258,
    'NodeIKernelGroupService/inviteMembersToGroupWithMsg': 0x1189614,
    'NodeIKernelGroupService/createGroup': 0x1189cae,
    'NodeIKernelGroupService/createGroupWithMembers': 0x118a3e0,
    'NodeIKernelGroupService/createGroupV2': 0x118a82c,
    'NodeIKernelGroupService/quitGroup': 0x118afca,
    'NodeIKernelGroupService/quitGroupV2': 0x118b2ec,
    'NodeIKernelGroupService/destroyGroup': 0x118b67c,
    'NodeIKernelGroupService/destroyGroupV2': 0x118b99e,
    'NodeIKernelGroupService/getSingleScreenNotifies': 0x118bbec,
    'NodeIKernelGroupService/clearGroupNotifies': 0x118bf3e,
    'NodeIKernelGroupService/getGroupNotifiesUnreadCount': 0x118c176,
    'NodeIKernelGroupService/clearGroupNotifiesUnreadCount': 0x118c3ae,
    'NodeIKernelGroupService/operateSysNotify': 0x118c5e6,
    'NodeIKernelGroupService/setTop': 0x118ca4c,
    'NodeIKernelGroupService/getGroupBulletin': 0x118cd84,
    'NodeIKernelGroupService/deleteGroupBulletin': 0x118d0a6,
    'NodeIKernelGroupService/publishGroupBulletin': 0x118d4a8,
    'NodeIKernelGroupService/publishInstructionForNewcomers': 0x118dd9e,
    'NodeIKernelGroupService/uploadGroupBulletinPic': 0x118e21c,
    'NodeIKernelGroupService/downloadGroupBulletinRichMedia': 0x118e65c,
    'NodeIKernelGroupService/getGroupBulletinList': 0x118eb1a,
    'NodeIKernelGroupService/getGroupBulletinDetail': 0x118f070,
    'NodeIKernelGroupService/remindGroupBulletinRead': 0x118f4b0,
    'NodeIKernelGroupService/getGroupBulletinReadUsers': 0x118f8b2,
    'NodeIKernelGroupService/getGroupStatisticInfo': 0x118fd4a,
    'NodeIKernelGroupService/getGroupRemainAtTimes': 0x119006c,
    'NodeIKernelGroupService/getJoinGroupNoVerifyFlag': 0x11903ca,
    'NodeIKernelGroupService/getGroupArkInviteState': 0x1190756,
    'NodeIKernelGroupService/reqToJoinGroup': 0x1190bf8,
    'NodeIKernelGroupService/joinGroup': 0x119182e,
    'NodeIKernelGroupService/setHeader': 0x1191b86,
    'NodeIKernelGroupService/setGroupShutUp': 0x1191f12,
    'NodeIKernelGroupService/getGroupShutUpMemberList': 0x119224a,
    'NodeIKernelGroupService/setMemberShutUp': 0x119256c,
    'NodeIKernelGroupService/getGroupRecommendContactArkJson': 0x1192b6a,
    'NodeIKernelGroupService/getJoinGroupLink': 0x1192ec8,
    'NodeIKernelGroupService/modifyGroupExtInfo': 0x119341c,
    'NodeIKernelGroupService/modifyGroupExtInfoV2': 0x119394c,
    'NodeIKernelGroupService/operateSpecialFocus': 0x1193cc0,
    'NodeIKernelGroupService/getGroupRecommendContactArkJsonToWechat': 0x11943ba,
    'NodeIKernelGroupService/getGroupDBVersion': 0x11946dc,
    'NodeIKernelGroupService/getGroupHonorList': 0x119483e,
    'NodeIKernelGroupService/getUidByUins': 0x1194cea,
    'NodeIKernelGroupService/getUinByUids': 0x11950e0,
    'NodeIKernelGroupService/checkGroupMemberCache': 0x1195512,
    'NodeIKernelGroupService/setGroupRelationToGuild': 0x1195908,
    'NodeIKernelGroupService/getGroupBindGuilds': 0x1195e7a,
    'NodeIKernelGroupService/unbindAllGuilds': 0x119628a,
    'NodeIKernelGroupService/setAIOBindGuild': 0x11964fa,
    'NodeIKernelGroupService/queryAIOBindGuild': 0x1196960,
    'NodeIKernelGroupService/getAIOBindGuildInfo': 0x1196d50,
    'NodeIKernelGroupService/updateMemberInfoByMqq': 0x119722e,
    'NodeIKernelGroupService/removeGroupFromGroupList': 0x11976c6,
    'NodeIKernelGroupService/getSubGroupInfo': 0x11978c2,
    'NodeIKernelGroupService/queryJoinGroupCanNoVerify': 0x1197b32,
    'NodeIKernelGroupService/setActiveExtGroup': 0x1198166,
    'NodeIKernelGroupService/setRcvJoinVerifyMsg': 0x1198660,
    'NodeIKernelGroupService/setGroupGeoInfo': 0x1198c5e,
    'NodeIKernelGroupService/updateGroupInfoByMqq': 0x1199312,
    'NodeIKernelGroupService/getAllGroupPrivilegeFlag': 0x1199d86,
    'NodeIKernelGroupService/getSwitchStatusForEssenceMsg': 0x119a18a,
    'NodeIKernelGroupService/getGroupMemberMaxNum': 0x119a4e8,
    'NodeIKernelGroupService/getGroupSecLevelInfo': 0x119a854,
    'NodeIKernelGroupService/getGroupAvatarWall': 0x119abc0,
    'NodeIKernelGroupService/getGroupSeqAndJoinTimeForGrayTips': 0x119af1e,
    'NodeIKernelGroupService/getGroupInfoForJoinGroup': 0x119b27c,
    'NodeIKernelGroupService/getGroupPayToJoinStatus': 0x119b60a,
    'NodeIKernelGroupService/getGroupMsgLimitFreq': 0x119b968,
    'NodeIKernelGroupService/getGroupTagRecords': 0x119bcc6,
    'NodeIKernelGroupService/getGroupFlagForThirdApp': 0x119c024,
    'NodeIKernelGroupService/getGroupInviteNoAuthLimitNum': 0x119c41a,
    'NodeIKernelGroupService/getGroupLatestEssenceList': 0x119c810,
    'NodeIKernelGroupService/addGroupEssence': 0x119cf80,
    'NodeIKernelGroupService/removeGroupEssence': 0x119d390,
    'NodeIKernelGroupService/getGroupMemberLevelInfo': 0x119d5de,
    'NodeIKernelGroupService/isEssenceMsg': 0x119d900,
    'NodeIKernelGroupService/queryCachedEssenceMsg': 0x119db8a,
    'NodeIKernelGroupService/shareDigest': 0x119de14,
    'NodeIKernelGroupService/fetchGroupEssenceList': 0x119e60e,
    'NodeIKernelGroupService/getFindPageRecommendGroup': 0x119eac2,
    'NodeIKernelSearchService/addKernelSearchListener': 0x11b31e8,
    'NodeIKernelSearchService/removeKernelSearchListener': 0x11b34d0,
    'NodeIKernelSearchService/searchStranger': 0x11b36ca,
    'NodeIKernelSearchService/searchGroup': 0x11b4474,
    'NodeIKernelSearchService/searchRobot': 0x11b4cf4,
    'NodeIKernelSearchService/searchLocalInfo': 0x11b526e,
    'NodeIKernelSearchService/cancelSearchLocalInfo': 0x11b5580,
    'NodeIKernelSearchService/searchBuddyChatInfo': 0x11b574c,
    'NodeIKernelSearchService/searchMoreBuddyChatInfo': 0x11b5b60,
    'NodeIKernelSearchService/cancelSearchBuddyChatInfo': 0x11b5c90,
    'NodeIKernelSearchService/searchContact': 0x11b5e5c,
    'NodeIKernelSearchService/searchMoreContact': 0x11b640c,
    'NodeIKernelSearchService/cancelSearchContact': 0x11b653c,
    'NodeIKernelSearchService/searchGroupChatInfo': 0x11b6708,
    'NodeIKernelSearchService/resetSearchGroupChatInfoSortType': 0x11b6e60,
    'NodeIKernelSearchService/resetSearchGroupChatInfoFilterMembers': 0x11b6fda,
    'NodeIKernelSearchService/searchMoreGroupChatInfo': 0x11b72d4,
    'NodeIKernelSearchService/cancelSearchGroupChatInfo': 0x11b7406,
    'NodeIKernelSearchService/searchChatsWithKeywords': 0x11b75d6,
    'NodeIKernelSearchService/searchMoreChatsWithKeywords': 0x11b7a0e,
    'NodeIKernelSearchService/cancelSearchChatsWithKeywords': 0x11b7b40,
    'NodeIKernelSearchService/searchChatMsgs': 0x11b7d10,
    'NodeIKernelSearchService/searchMoreChatMsgs': 0x11b8a50,
    'NodeIKernelSearchService/cancelSearchChatMsgs': 0x11b8b82,
    'NodeIKernelSearchService/searchMsgWithKeywords': 0x11b8d52,
    'NodeIKernelSearchService/searchMoreMsgWithKeywords': 0x11b936c,
    'NodeIKernelSearchService/cancelSearchMsgWithKeywords': 0x11b949e,
    'NodeIKernelSearchService/searchFileWithKeywords': 0x11b966e,
    'NodeIKernelSearchService/searchMoreFileWithKeywords': 0x11b9a86,
    'NodeIKernelSearchService/cancelSearchFileWithKeywords': 0x11b9bb8,
    'NodeIKernelSearchService/searchAtMeChats': 0x11b9d88,
    'NodeIKernelSearchService/searchMoreAtMeChats': 0x11ba00e,
    'NodeIKernelSearchService/cancelSearchAtMeChats': 0x11ba140,
    'NodeIKernelSearchService/searchChatAtMeMsgs': 0x11ba310,
    'NodeIKernelSearchService/searchMoreChatAtMeMsgs': 0x11ba75a,
    'NodeIKernelSearchService/cancelSearchChatAtMeMsgs': 0x11ba88c,
    'NodeIKernelSearchService/loadSearchHistory': 0x11baa5c,
    'NodeIKernelSearchService/clearSearchHistory': 0x11bacba,
    'NodeIKernelSearchService/addSearchHistory': 0x11baeda,
    'NodeIKernelSearchService/removeSearchHistory': 0x11bba40,
    'NodeIKernelSearchService/searchCache': 0x11bbc6c,
    'NodeIKernelSearchService/clearSearchCache': 0x11bbf90,
    'NodeIKernelBuddyService/addKernelBuddyListener': 0x11c62f0,
    'NodeIKernelBuddyService/removeKernelBuddyListener': 0x11c65d8,
    'NodeIKernelBuddyService/getBuddyList': 0x11c67d2,
    'NodeIKernelBuddyService/getBuddyNick': 0x11c6a06,
    'NodeIKernelBuddyService/getBuddyRemark': 0x11c6dfc,
    'NodeIKernelBuddyService/setBuddyRemark': 0x11c71f2,
    'NodeIKernelBuddyService/isBuddy': 0x11c78d0,
    'NodeIKernelBuddyService/getCategoryNameWithUid': 0x11c7ab4,
    'NodeIKernelBuddyService/getTargetBuddySetting': 0x11c7cfa,
    'NodeIKernelBuddyService/getTargetBuddySettingByType': 0x11c7fd2,
    'NodeIKernelBuddyService/getBuddyReqUnreadCnt': 0x11c8384,
    'NodeIKernelBuddyService/getBuddyReq': 0x11c85a0,
    'NodeIKernelBuddyService/delBuddyReq': 0x11c87bc,
    'NodeIKernelBuddyService/clearBuddyReqUnreadCnt': 0x11c8cbe,
    'NodeIKernelBuddyService/reqToAddFriends': 0x11c8eda,
    'NodeIKernelBuddyService/setSpacePermission': 0x11c9ef8,
    'NodeIKernelBuddyService/approvalFriendRequest': 0x11ca440,
    'NodeIKernelBuddyService/delBuddy': 0x11caa66,
    'NodeIKernelBuddyService/delBatchBuddy': 0x11caeb6,
    'NodeIKernelBuddyService/getSmartInfos': 0x11cb2b6,
    'NodeIKernelBuddyService/setBuddyCategory': 0x11cb592,
    'NodeIKernelBuddyService/setBatchBuddyCategory': 0x11cb87e,
    'NodeIKernelBuddyService/addCategory': 0x11cbc7c,
    'NodeIKernelBuddyService/delCategory': 0x11cbf58,
    'NodeIKernelBuddyService/renameCategory': 0x11cc184,
    'NodeIKernelBuddyService/resortCategory': 0x11cc470,
    'NodeIKernelBuddyService/pullCategory': 0x11cc9bc,
    'NodeIKernelBuddyService/setTop': 0x11ccbdc,
    'NodeIKernelBuddyService/SetSpecialCare': 0x11cced0,
    'NodeIKernelBuddyService/setMsgNotify': 0x11cd2b6,
    'NodeIKernelBuddyService/hasBuddyList': 0x11cd5aa,
    'NodeIKernelBuddyService/setBlock': 0x11cd6f8,
    'NodeIKernelBuddyService/isBlocked': 0x11cd9ec,
    'NodeIKernelBuddyService/modifyAddMeSetting': 0x11cdbd2,
    'NodeIKernelBuddyService/getAddMeSetting': 0x11cdee2,
    'NodeIKernelBuddyService/getDoubtBuddyReq': 0x11ce102,
    'NodeIKernelBuddyService/getDoubtBuddyUnreadNum': 0x11ce45e,
    'NodeIKernelBuddyService/approvalDoubtBuddyReq': 0x11ce67e,
    'NodeIKernelBuddyService/delDoubtBuddyReq': 0x11cebb2,
    'NodeIKernelBuddyService/delAllDoubtBuddyReq': 0x11cee8e,
    'NodeIKernelBuddyService/reportDoubtBuddyReqUnread': 0x11cf0ae,
    'NodeIKernelBuddyService/getBuddyRecommendContactArkJson': 0x11cf2ce,
    'NodeIKernelBuddyService/getBuddyListV2': 0x11cf696,
    'NodeIKernelBuddyService/getBuddyListFromCache': 0x11cf92c,
    'NodeIKernelBuddyService/getCategoryById': 0x11cfd36,
    'NodeIKernelBuddyService/getAllBuddyCount': 0x11cffc2,
    'NodeIKernelBuddyService/isNewBuddylistVersion': 0x11d0110,
    'NodeIKernelMSFService/online': 0x11d2608,
    'NodeIKernelMSFService/offline': 0x11d2754,
    'NodeIKernelMSFService/getServerTime': 0x11d28a0,
    'NodeIKernelMSFService/getMsfStatus': 0x11d2a24,
    'NodeIKernelMSFService/getNetworkProxy': 0x11d2b70,
    'NodeIKernelMSFService/getBrowserAndSetLocalProxy': 0x11d2dca,
    'NodeIKernelMSFService/setNetworkProxy': 0x11d2ffe,
    'NodeIKernelMSFService/setNetworkProxySaveDir': 0x11d3762,
    'NodeIKernelMSFService/testNetworkProxyConnection': 0x11d390c,
    'NodeIKernelNodeMiscService/addKernelNodeMiscListener': 0x11d41a0,
    'NodeIKernelNodeMiscService/removeKernelNodeMiscListener': 0x11d43ea,
    'NodeIKernelNodeMiscService/startSession': 0x11d45f6,
    'NodeIKernelNodeMiscService/encodeAES': 0x11d4a4e,
    'NodeIKernelNodeMiscService/getUserDataDir': 0x11d4d46,
    'NodeIKernelNodeMiscService/setCurActiveGuildAndChannel': 0x11d4ecc,
    'NodeIKernelNodeMiscService/setCurWindowsStatus': 0x11d516e,
    'NodeIKernelNodeMiscService/openPictureUsingQQ': 0x11d54f2,
    'NodeIKernelNodeMiscService/initScreenShotPlugin': 0x11d5674,
    'NodeIKernelNodeMiscService/setScreenShotSetting': 0x11d578c,
    'NodeIKernelNodeMiscService/wantScreenShot': 0x11d58a4,
    'NodeIKernelNodeMiscService/wantScreenShotWithLinuxX11Lib': 0x11d59bc,
    'NodeIKernelNodeMiscService/wantScreenRecording': 0x11d5c16,
    'NodeIKernelNodeMiscService/startScreenShotInstance': 0x11d5d2e,
    'NodeIKernelNodeMiscService/wantScreenShotNT': 0x11d5e46,
    'NodeIKernelNodeMiscService/wantScreenRecordingNT': 0x11d5f78,
    'NodeIKernelNodeMiscService/wantScreenOCR': 0x11d60aa,
    'NodeIKernelNodeMiscService/wantWinScreenOCR': 0x11d6256,
    'NodeIKernelNodeMiscService/cancelOCRImage': 0x11d6532,
    'NodeIKernelNodeMiscService/registerScreenRecordShortcutWithKeycode': 0x11d6650,
    'NodeIKernelNodeMiscService/registerScreenCaptureShortcutWithKeycode': 0x11d67fc,
    'NodeIKernelNodeMiscService/unregisterHotkey': 0x11d69a8,
    'NodeIKernelNodeMiscService/isScreenCaptureOrRecording': 0x11d6ba4,
    'NodeIKernelNodeMiscService/getGetFullScreenInfo': 0x11d6cf2,
    'NodeIKernelNodeMiscService/getWindowsMenuInstallStatus': 0x11d6ef0,
    'NodeIKernelNodeMiscService/setWindowsMenuInstallStatus': 0x11d703e,
    'NodeIKernelNodeMiscService/startScreenCapture': 0x11d7170,
    'NodeIKernelNodeMiscService/endScreenCapture': 0x11d732c,
    'NodeIKernelNodeMiscService/getDisplayInfo': 0x11d744a,
    'NodeIKernelNodeMiscService/getWindowsInfo': 0x11d7568,
    'NodeIKernelNodeMiscService/cleanWindowsInfo': 0x11d7686,
    'NodeIKernelNodeMiscService/getCurWindowInfo': 0x11d77a4,
    'NodeIKernelNodeMiscService/setWindowPos': 0x11d7abe,
    'NodeIKernelNodeMiscService/startScreenCaptureDetect': 0x11d7cd0,
    'NodeIKernelNodeMiscService/startScreenCaptureDetectByBuf': 0x11d7ee8,
    'NodeIKernelNodeMiscService/checkIsSupportAutoDetect': 0x11d812c,
    'NodeIKernelNodeMiscService/startScreenCaptureLong': 0x11d838a,
    'NodeIKernelNodeMiscService/setWindowLevelNT': 0x11d855e,
    'NodeIKernelNodeMiscService/setWindowLayerNT': 0x11d8754,
    'NodeIKernelNodeMiscService/callLongCaptureExit': 0x11d8900,
    'NodeIKernelNodeMiscService/listenWindowEvents': 0x11d8a1e,
    'NodeIKernelNodeMiscService/unlistenWindowEvents': 0x11d8bca,
    'NodeIKernelNodeMiscService/setBackgroudWindowLevel': 0x11d8d76,
    'NodeIKernelNodeMiscService/listenMouseMoveOnDisplays': 0x11d8f32,
    'NodeIKernelNodeMiscService/unlistenMouseMoveOnDisplays': 0x11d9050,
    'NodeIKernelNodeMiscService/isDwmCompositionEnabled': 0x11d916e,
    'NodeIKernelNodeMiscService/deleteShareFile': 0x11d92bc,
    'NodeIKernelNodeMiscService/scanQBar': 0x11d9468,
    'NodeIKernelNodeMiscService/registerServiceMenu': 0x11d9782,
    'NodeIKernelNodeMiscService/isAppInstalled': 0x11d98a0,
    'NodeIKernelNodeMiscService/installApp': 0x11da016,
    'NodeIKernelNodeMiscService/startNewApp': 0x11da1e2,
    'NodeIKernelNodeMiscService/sendRequestToApiGateway': 0x11da36a,
    'NodeIKernelNodeMiscService/getQzoneUnreadCount': 0x11dac46,
    'NodeIKernelNodeMiscService/clearQzoneUnreadCount': 0x11dafa6,
    'NodeIKernelNodeMiscService/getOpenAuth': 0x11db33a,
    'NodeIKernelNodeMiscService/getOpenAuthDelegateCode': 0x11db66c,
    'NodeIKernelNodeMiscService/wantParseClipboard': 0x11dba50,
    'NodeIKernelNodeMiscService/writeBitmapToClipboard': 0x11dbcae,
    'NodeIKernelNodeMiscService/wantParseMultiClipboard': 0x11dbfc8,
    'NodeIKernelNodeMiscService/mainWindowInitComplete': 0x11dc226,
    'NodeIKernelNodeMiscService/notifyGuildHasHiddenDock': 0x11dc344,
    'NodeIKernelNodeMiscService/changeSendKey': 0x11dc462,
    'NodeIKernelNodeMiscService/getSendKey': 0x11dc594,
    'NodeIKernelNodeMiscService/needRelaunchQQGuild': 0x11dc7f2,
    'NodeIKernelNodeMiscService/getNodeAndQQIPCVersions': 0x11dc99e,
    'NodeIKernelNodeMiscService/getRelaunchParams': 0x11dcb9c,
    'NodeIKernelNodeMiscService/writeClipboard': 0x11dcdfa,
    'NodeIKernelNodeMiscService/writeMultiClipboard': 0x11dd2c0,
    'NodeIKernelNodeMiscService/checkIfHaveAvailableSidecarDevice': 0x11dd92a,
    'NodeIKernelNodeMiscService/openSidecarMenu': 0x11dda5c,
    'NodeIKernelNodeMiscService/startNewAppInstance': 0x11ddd10,
    'NodeIKernelNodeMiscService/startNewMiniApp': 0x11dde2e,
    'NodeIKernelNodeMiscService/sendMiniAppMsg': 0x11de1b0,
    'NodeIKernelNodeMiscService/getAppInfoByLink': 0x11de482,
    'NodeIKernelNodeMiscService/setMiniAppVersion': 0x11de7aa,
    'NodeIKernelNodeMiscService/getMiniAppPath': 0x11de956,
    'NodeIKernelNodeMiscService/isMiniAppExist': 0x11deae0,
    'NodeIKernelNodeMiscService/isMiniAppAlreadyExist': 0x11dec2e,
    'NodeIKernelNodeMiscService/downloadMiniApp': 0x11ded7c,
    'NodeIKernelNodeMiscService/cancelDownloadMiniApp': 0x11df096,
    'NodeIKernelNodeMiscService/setMiniGameVersion': 0x11df2b6,
    'NodeIKernelNodeMiscService/getMiniGamePath': 0x11df462,
    'NodeIKernelNodeMiscService/isMiniGameExist': 0x11df5ec,
    'NodeIKernelNodeMiscService/isMiniGameAlreadyExist': 0x11df73a,
    'NodeIKernelNodeMiscService/downloadMiniGame': 0x11df888,
    'NodeIKernelNodeMiscService/cancelDownloadMiniGame': 0x11dfb64,
    'NodeIKernelNodeMiscService/getMiniGameV2EngineConfig': 0x11dfd84,
    'NodeIKernelNodeMiscService/openFileAndDirSelectDlg': 0x11e009e,
    'NodeIKernelNodeMiscService/flashWindowInTaskbar': 0x11e0aac,
    'NodeIKernelNodeMiscService/stopFlashWindow': 0x11e0cb6,
    'NodeIKernelNodeMiscService/registerSchemes': 0x11e0eb2,
    'NodeIKernelNodeMiscService/writeVersionToRegistry': 0x11e1098,
    'NodeIKernelNodeMiscService/setAutoRun': 0x11e127e,
    'NodeIKernelNodeMiscService/delAutoRun': 0x11e13cc,
    'NodeIKernelNodeMiscService/queryAutoRun': 0x11e151a,
    'NodeIKernelNodeMiscService/prefetch': 0x11e1668,
    'NodeIKernelNodeMiscService/getGroupOpenID': 0x11e1814,
    'NodeIKernelNodeMiscService/getRelationUinToOpenID': 0x11e1c0a,
    'NodeIKernelNodeMiscService/getGroupMemberOpenID': 0x11e2066,
    'NodeIKernelNodeMiscService/isOldQQRunning': 0x11e2550,
    'NodeIKernelNodeMiscService/getConcernWeather': 0x11e28ae,
    'NodeIKernelNodeMiscService/getQQlevelInfo': 0x11e2b0c,
    'NodeIKernelNodeMiscService/verifyCaptchaTicket': 0x11e2e6a,
    'NodeIKernelNodeMiscService/qqConnectShareCheck': 0x11e32aa,
    'NodeIKernelNodeMiscService/qqConnectShare': 0x11e4490,
    'NodeIKernelNodeMiscService/qqConnectBatchShare': 0x11e5792,
    'NodeIKernelNodeMiscService/openIDToUin': 0x11e6350,
    'NodeIGuildHotUpdateService/addHotUpdateListener': 0x11ececc,
    'NodeIGuildHotUpdateService/removeHotUpdateListener': 0x11ed116,
    'NodeIKernelMsgBackupService/addKernelMsgBackupListener': 0x11ed8b0,
    'NodeIKernelMsgBackupService/removeKernelMsgBackupListener': 0x11edafa,
    'NodeIKernelMsgBackupService/getMsgBackupLocation': 0x11edd06,
    'NodeIKernelMsgBackupService/setMsgBackupLocation': 0x11edf60,
    'NodeIKernelMsgBackupService/requestMsgBackup': 0x11ee238,
    'NodeIKernelMsgBackupService/requestMsgRestore': 0x11ee492,
    'NodeIKernelMsgBackupService/requestMsgMigrate': 0x11eec2c,
    'NodeIKernelMsgBackupService/getLocalStorageBackup': 0x11eeed8,
    'NodeIKernelMsgBackupService/deleteLocalBackup': 0x11ef132,
    'NodeIKernelMsgBackupService/clearCache': 0x11efa1a,
    'NodeIKernelMsgBackupService/start': 0x11efb32,
    'NodeIKernelMsgBackupService/stop': 0x11efd2c,
    'NodeIKernelMsgBackupService/pause': 0x11eff26,
    'NodeIKernelMsgBackupService/setMsgBackupDataHandlingOption': 0x11f0136,
    'NodeIKernelRemotingService/addKernelRemotingListener': 0x11f0c7c,
    'NodeIKernelRemotingService/removeKernelRemotingListener': 0x11f0ec6,
    'NodeIKernelRemotingService/setPenetrateBuffer': 0x11f10d2,
    'NodeIKernelRemotingService/startRemotingClient': 0x11f129e,
    'NodeIKernelRemotingService/startRemotingInvite': 0x11f1498,
    'NodeIKernelRemotingService/stopRemoting': 0x11f1692,
    'NodeIKernelRemotingService/accept': 0x11f188c,
    'NodeIKernelAVSDKService/addKernelAVSDKListener': 0x11f2028,
    'NodeIKernelAVSDKService/removeKernelAVSDKListener': 0x11f2272,
    'NodeIKernelAVSDKService/setActionFromAVSDK': 0x11f247e,
    'NodeIKernelAVSDKService/allowAlbumNotify': 0x11f260e,
    'NodeIKernelAVSDKService/sendGroupVideoJsonBuffer': 0x11f2726,
    'NodeIKernelAVSDKService/startGroupVideoCmdRequestFromAVSDK': 0x11f28de,
    'NodeIKernelAVSDKService/checkDependencies': 0x11f2c6a
};

const globalNativeCallbacks = [];
const callLogMap = new Map();

function getThreadId() {
    try {
        return Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0;
    } catch {
        return 0;
    }
}

function getCallId() {
    return `${Date.now()}_${getThreadId()}_${Math.floor(Math.random() * 100000)}`;
}

function formatLog(logLines, callId, funcName) {
    const border = '━'.repeat(45);
    let out = [];
    out.push(`\n\x1b[36m┏${border}\x1b[0m`);
    out.push(`\x1b[36m┃ 调用: ${funcName}  [${callId}]\x1b[0m`);
    logLines.forEach(line => {
        // 参数和返回值缩进
        if (line.startsWith('[arg]')) {
            out.push(`\x1b[32m┣ 参数: ${line.replace('[arg]', '').trim()}\x1b[0m`);
        } else if (line.startsWith('[Promise]')) {
            out.push(`\x1b[35m┣ Promise: ${line.replace('[Promise]', '').trim()}\x1b[0m`);
        } else if (line.startsWith('---- 返回值 ----')) {
            out.push(`\x1b[33m┣ 返回值:\x1b[0m`);
        } else if (line.startsWith('[!]')) {
            out.push(`\x1b[31m┣ 错误: ${line.replace('[!]', '').trim()}\x1b[0m`);
        } else if (line.startsWith('====')) {
            // 跳过
        } else {
            out.push(`\x1b[32m┣ ${line.replace('[arg]', '').trim()}\x1b[0m`);
        }
    });
    out.push(`\x1b[36m┗${border}\x1b[0m\n`);
    return out.join('\n');
}

function printNapiValue(env, value, logLines) {
    if (!value || value.isNull && value.isNull()) {
        logLines.push('[arg] value is NULL');
        return;
    }
    var napi_typeof_addr = Module.findExportByName('qqnt.dll', 'napi_typeof');
    var napi_typeof_fn = new NativeFunction(napi_typeof_addr, 'int', ['pointer', 'pointer', 'pointer']);
    var type_ptr = Memory.alloc(4);
    var status = napi_typeof_fn(env, value, type_ptr);
    if (status !== 0) {
        logLines.push('[!] napi_typeof failed: ' + status);
        return;
    }
    var type = type_ptr.readU32();
    switch (type) {
        case 0: logLines.push('[arg] type: undefined'); break;
        case 1: logLines.push('[arg] type: null'); break;
        case 2: { // boolean
            var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_bool'), 'int', ['pointer', 'pointer', 'pointer']);
            var ptr = Memory.alloc(4);
            if (fn(env, value, ptr) === 0) logLines.push('[arg] type: boolean, value: ' + (ptr.readU32() ? 'true' : 'false'));
            else logLines.push('[arg] type: boolean, value: <error>');
            break;
        }
        case 3: { // number
            var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_double'), 'int', ['pointer', 'pointer', 'pointer']);
            var ptr = Memory.alloc(8);
            if (fn(env, value, ptr) === 0) logLines.push('[arg] type: number, value: ' + ptr.readDouble());
            else logLines.push('[arg] type: number, value: <error>');
            break;
        }
        case 4: { // string
            var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8'), 'int', ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']);
            var buf = Memory.alloc(1024), copied = Memory.alloc(8);
            if (fn(env, value, buf, 1023, copied) === 0) logLines.push('[arg] type: string, value: ' + buf.readUtf8String());
            else logLines.push('[arg] type: string, value: <error>');
            break;
        }
        case 6: { // object
            try {
                var napi_get_global = Module.findExportByName('qqnt.dll', 'napi_get_global');
                var napi_get_global_fn = napi_get_global ? new NativeFunction(napi_get_global, 'int', ['pointer', 'pointer']) : null;
                var global_ptr = Memory.alloc(Process.pointerSize);
                if (napi_get_global_fn) napi_get_global_fn(env, global_ptr);
                else {
                    var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
                    var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
                    var global_name = Memory.allocUtf8String("globalThis");
                    napi_get_named_property_fn(env, env, global_name, global_ptr);
                }
                var global_obj = global_ptr.readPointer();
                var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
                var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
                var json_name = Memory.allocUtf8String("JSON");
                var json_ptr = Memory.alloc(Process.pointerSize);
                napi_get_named_property_fn(env, global_obj, json_name, json_ptr);
                var json_obj = json_ptr.readPointer();
                var stringify_name = Memory.allocUtf8String("stringify");
                var stringify_ptr = Memory.alloc(Process.pointerSize);
                napi_get_named_property_fn(env, json_obj, stringify_name, stringify_ptr);
                var stringify_fn = stringify_ptr.readPointer();
                var napi_call_function = Module.findExportByName('qqnt.dll', 'napi_call_function');
                var napi_call_function_fn = new NativeFunction(napi_call_function, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'pointer', 'pointer']);
                var stringify_argv = Memory.alloc(Process.pointerSize);
                stringify_argv.writePointer(value);
                var stringify_result_ptr = Memory.alloc(Process.pointerSize);
                if (napi_call_function_fn(env, json_obj, stringify_fn, 1, stringify_argv, stringify_result_ptr) === 0) {
                    var fn = new NativeFunction(Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8'), 'int', ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']);
                    var buf = Memory.alloc(4096), copied = Memory.alloc(8);
                    fn(env, stringify_result_ptr.readPointer(), buf, 4095, copied);
                    logLines.push('[arg] type: object, JSON: ' + buf.readUtf8String());
                } else {
                    logLines.push('[arg] type: object, JSON: <stringify error>');
                }
            } catch (e) {
                logLines.push('[arg] type: object, JSON: <exception> ' + e);
            }
            break;
        }
        case 9: { // bigint
            var addr = Module.findExportByName('qqnt.dll', 'napi_get_value_bigint_words');
            if (addr) {
                var fn = new NativeFunction(addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
                var sign_ptr = Memory.alloc(4), word_count_ptr = Memory.alloc(8);
                word_count_ptr.writeU64(4);
                var words_ptr = Memory.alloc(8 * 4);
                if (fn(env, value, sign_ptr, word_count_ptr, words_ptr) === 0) {
                    var sign = sign_ptr.readU32(), word_count = word_count_ptr.readU64();
                    var words = [];
                    for (var i = 0; i < word_count; i++) words.push(words_ptr.add(i * 8).readU64());
                    var hex = words.map(w => w.toString(16).padStart(16, '0')).reverse().join('');
                    var prefix = sign ? '-' : '';
                    logLines.push('[arg] type: bigint, value: ' + prefix + '0x' + hex);
                } else {
                    logLines.push('[arg] type: bigint, value: <error>');
                }
            } else {
                logLines.push('[arg] type: bigint, value: <napi_get_value_bigint_words not found>');
            }
            break;
        }
        default: logLines.push('[arg] type: ' + type);
    }
}

function isPromise(env, value) {
    try {
        var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
        var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        var constructor_name = Memory.allocUtf8String("constructor");
        var constructor_ptr = Memory.alloc(Process.pointerSize);
        if (napi_get_named_property_fn(env, value, constructor_name, constructor_ptr) !== 0) return false;
        var constructor = constructor_ptr.readPointer();

        var name_name = Memory.allocUtf8String("name");
        var name_ptr = Memory.alloc(Process.pointerSize);
        if (napi_get_named_property_fn(env, constructor, name_name, name_ptr) !== 0) return false;
        var napi_get_value_string_utf8 = Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8');
        var napi_get_value_string_utf8_fn = new NativeFunction(napi_get_value_string_utf8, 'int', ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']);
        var buf = Memory.alloc(64), copied = Memory.alloc(8);
        if (napi_get_value_string_utf8_fn(env, name_ptr.readPointer(), buf, 63, copied) !== 0) return false;
        var name = buf.readUtf8String();
        return name === "Promise";
    } catch (e) {
        return false;
    }
}

function callPromiseThen(env, promise, logLines, callId, funcName) {
    try {
        var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
        var napi_get_named_property_fn = new NativeFunction(napi_get_named_property, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        var then_name = Memory.allocUtf8String("then");
        var then_ptr = Memory.alloc(Process.pointerSize);
        if (napi_get_named_property_fn(env, promise, then_name, then_ptr) !== 0) {
            logLines.push('[Promise] 获取 then 方法失败');
            console.log(formatLog(logLines, callId, funcName));
            return;
        }
        var then_fn = then_ptr.readPointer();

        var napi_create_function = Module.findExportByName('qqnt.dll', 'napi_create_function');
        var napi_create_function_fn = new NativeFunction(napi_create_function, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
        var cb_name = Memory.allocUtf8String("onPromiseResolved");
        var cb_ptr = Memory.alloc(Process.pointerSize);

        // 1. 定义回调函数
        var onResolved = new NativeCallback(function (env_, cbinfo) {
            try {
                var napi_get_cb_info = Module.findExportByName('qqnt.dll', 'napi_get_cb_info');
                var napi_get_cb_info_fn = new NativeFunction(napi_get_cb_info, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
                var argc_ptr = Memory.alloc(8); argc_ptr.writeU64(1);
                var argv_ptr = Memory.alloc(Process.pointerSize);
                napi_get_cb_info_fn(env_, cbinfo, argc_ptr, argv_ptr, ptr(0), ptr(0));
                var arg_ptr = argv_ptr.readPointer();

                // 2. 直接打印Promise resolve的值
                var lines = [];
                lines.push('[Promise] resolve:');
                printNapiValue(env_, arg_ptr, lines);
                lines.push('==== call end ====');

                // 取出主调用的logLines，合并Promise resolve内容
                let mainLogLines = callLogMap.get(callId);
                if (mainLogLines) {
                    lines.forEach(l => mainLogLines.push(l));
                    console.log(formatLog(mainLogLines, callId, funcName));
                    callLogMap.delete(callId);
                } else {
                    // fallback
                    console.log(formatLog(lines, callId, funcName));
                }
            } catch (e) {
                console.log('[Promise] resolve回调异常: ' + e);
            }
            if(globalNativeCallbacks.includes(onResolved)) {
                var index = globalNativeCallbacks.indexOf(onResolved);
                if (index !== -1) {
                    globalNativeCallbacks.splice(index, 1);
                }
            }
            return ptr(0);
        }, 'pointer', ['pointer', 'pointer']);

        // 3. 防止GC回收
        globalNativeCallbacks.push(onResolved);

        // 4. 创建JS function对象
        var status = napi_create_function_fn(env, cb_name, ptr(0), onResolved, ptr(0), cb_ptr);
        if (status !== 0) {
            logLines.push('[Promise] 创建回调函数失败: ' + status);
            logLines.push('==== call end ====');
            console.log(formatLog(logLines, callId, funcName));
            return;
        }

        // 5. 调用then
        var napi_call_function = Module.findExportByName('qqnt.dll', 'napi_call_function');
        var napi_call_function_fn = new NativeFunction(napi_call_function, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'pointer', 'pointer']);
        var argv = Memory.alloc(Process.pointerSize);
        argv.writePointer(cb_ptr.readPointer());
        var callStatus = napi_call_function_fn(env, promise, then_fn, 1, argv, ptr(0));
        if (callStatus !== 0) {
            logLines.push('[Promise] then调用失败: ' + callStatus);
            logLines.push('==== call end ====');
            console.log(formatLog(logLines, callId, funcName));
        }
    } catch (e) {
        logLines.push('[Promise] then 调用异常: ' + e);
        logLines.push('==== call end ====');
        console.log(formatLog(logLines, callId, funcName));
    }
}

function hookNapiFunc(name, offset) {
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }
    var funcAddr = baseAddr.add(offset);
    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            this.callId = getCallId();
            this.funcName = name;
            this.logLines = [];
            var env = args[0], info = args[1];
            this.env = env; // 保存env用于onLeave
            var napi_get_cb_info = Module.findExportByName('qqnt.dll', 'napi_get_cb_info');
            var napi_get_cb_info_fn = new NativeFunction(napi_get_cb_info, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
            var argc_ptr = Memory.alloc(8); argc_ptr.writeU64(8);
            var argv_ptr = Memory.alloc(Process.pointerSize * 8);
            var status = napi_get_cb_info_fn(env, info, argc_ptr, argv_ptr, ptr(0), ptr(0));
            if (status !== 0) {
                this.logLines.push(`[!] napi_get_cb_info failed: ` + status);
                callLogMap.set(this.callId, this.logLines);
                return;
            }
            var argc = argc_ptr.readU64();
            this.logLines.push(`参数量: ` + argc);
            for (var i = 0; i < argc; i++) {
                var arg_ptr = argv_ptr.add(i * Process.pointerSize).readPointer();
                printNapiValue(env, arg_ptr, this.logLines);
            }
            callLogMap.set(this.callId, this.logLines);
        },
        onLeave: function (retval) {
            let logLines = callLogMap.get(this.callId) || [];
            logLines.push('---- 返回值 ----');
            try {
                if (retval.isNull() || retval.isZero && retval.isZero()) {
                    logLines.push(`空返回`);
                    console.log(formatLog(logLines, this.callId, this.funcName));
                    callLogMap.delete(this.callId);
                } else {
                    if (isPromise(this.env, retval)) {
                        // 不立即输出，等Promise resolve后输出
                        callPromiseThen(this.env, retval, logLines, this.callId, this.funcName);
                    } else {
                        printNapiValue(this.env, retval, logLines);
                        console.log(formatLog(logLines, this.callId, this.funcName));
                        callLogMap.delete(this.callId);
                    }
                }
            } catch (e) {
                logLines.push('[!] 返回值序列化异常: ' + e);
                console.log(formatLog(logLines, this.callId, this.funcName));
                callLogMap.delete(this.callId);
            }
        }
    });
}

function main() {
    // 1. 先hook wrapper.node导出函数
    for (const [name, offset] of Object.entries(target_func_list)) {
        hookNapiFunc(name, offset);
    }

    // 2. hook on*相关 napi_get_named_property 和 napi_call_function
    // 记录所有on*函数的function指针及其名称
    const onFunctionMap = new Map();

    // hook napi_get_named_property
    (function() {
        const addr = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.env = args[0];
                this.namePtr = args[2];
                this.resultPtr = args[3];
                try {
                    this.propName = Memory.readUtf8String(this.namePtr);
                } catch {
                    this.propName = '';
                }
                this.shouldLog = this.propName && this.propName.startsWith('on');
            },
            onLeave(retval) {
                if (!this.shouldLog) return;
                if (retval.toInt32() === 0) {
                    try {
                        const funcPtr = this.resultPtr.readPointer();
                        if (!funcPtr.isNull()) {
                            onFunctionMap.set(funcPtr.toString(), this.propName);
                        }
                    } catch {}
                }
            }
        });
    })();

    // hook napi_call_function
    (function() {
        const addr = Module.findExportByName('qqnt.dll', 'napi_call_function');
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                const env = args[0];
                const func = args[2];
                const argc = args[3].toInt32();
                const argv = args[4];

                const funcKey = func.toString();
                const funcName = onFunctionMap.get(funcKey);

                if (funcName && funcName.startsWith('on')) {
                    let logLines = [];
                    logLines.push(`[on] 调用on*函数: ${funcName} @ ${func}`);
                    logLines.push(`参数数量: ${argc}`);
                    for (let i = 0; i < argc; i++) {
                        try {
                            const argPtr = argv.add(i * Process.pointerSize).readPointer();
                            logLines.push(`[arg] 参数${i}:`);
                            printNapiValue(env, argPtr, logLines);
                        } catch (e) {
                            logLines.push(`[arg] 参数${i}: <exception: ${e}>`);
                        }
                    }
                    // 复用主日志格式
                    console.log(formatLog(logLines, 'on_' + funcKey, funcName));
                }
            }
        });
    })();
}

main();