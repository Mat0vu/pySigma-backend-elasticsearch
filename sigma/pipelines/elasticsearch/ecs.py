from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import FieldMappingTransformation, AddFieldnamePrefixTransformation, AddConditionTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def ecs_windows():
    return ProcessingPipeline(
        name="Elastic Common Schema (ECS) Windows log mappings",
        priority=20,
        items=[
            ProcessingItem(     # Windows log channels
                identifier=f"elasticsearch_windows_{service}",
                transformation=AddConditionTransformation({ "winlog.channel": source}),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(     # Field mappings
                identifier="ecs_windows_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "event.code",
                    "Channel": "winlog.channel",
                    "Provider_Name": "winlog.provider_name",
                    "ComputerName": "winlog.computer_name",
                    "FileName": "file.path",
                    "ProcessGuid": "process.entity_id",
                    "ProcessId": "process.pid",
                    "Image": "process.executable",
                    "CurrentDirectory": "process.working_directory",
                    "ParentProcessGuid": "process.parent.entity_id",
                    "ParentProcessId": "process.parent.pid",
                    "ParentImage": "process.parent.executable",
                    "ParentCommandLine": "process.parent.command_line",
                    "TargetFilename": "file.path",
                    "SourceIp": "source.ip",
                    "SourceHostname": "source.domain",
                    "SourcePort": "source.port",
                    "DestinationIp": "destination.ip",
                    "DestinationHostname": "destination.domain",
                    "DestinationPort": "destination.port",
                    "DestinationPortName": "network.protocol",
                    "ImageLoaded": "file.path",
                    "Signed": "file.code_signature.signed",
                    "SignatureStatus": "file.code_signature.status",
                    "SourceProcessGuid": "process.entity_id",
                    "SourceProcessId": "process.pid",
                    "SourceImage": "process.executable",
                    "Device": "file.path",
                    "SourceThreadId": "process.thread.id",
                    "TargetObject": "registry.path",
                    "PipeName": "file.name",
                    "Destination": "process.executable",
                    "QueryName": "dns.question.name",
                    "QueryStatus": "sysmon.dns.status",
                    "IsExecutable": "sysmon.file.is_executable",
                    "Archived": "sysmon.file.archived",
                    "CommandName": "powershell.command.name",
                    "CommandPath": "powershell.command.path",
                    "CommandType": "powershell.command.type",
                    "HostApplication": "process.command_line",
                    "HostId": "process.entity_id",
                    "HostName": "process.title",
                    "NewEngineState": "powershell.engine.new_state",
                    "PipelineId": "powershell.pipeline_id",
                    "PreviousEngineState": "powershell.engine.previous_state",
                    "RunspaceId": "powershell.runspace_id",
                    "ScriptName": "file.path",
                    "SequenceNumber": "event.sequence",
                    "NewProviderState": "powershell.provider.new_state",
                    "ProviderName": "powershell.provider.name",
                    "MessageNumber": "powershell.sequence",
                    "MessageTotal": "powershell.total",
                    "ScriptBlockText": "powershell.file.script_block_text",
                    "ScriptBlockId": "powershell.file.script_block_id",
                    "AccountDomain": "user.domain",
                    "AccountName": "user.name",
                    "Application": "process.executable",
                    "ClientAddress": "source.ip",
                    "ClientName": "source.domain",
                    "DestAddress": "destination.ip",
                    "DestPort": "destination.port",
                    "IpAddress": "source.ip",
                    "IpPort": "source.port",
                    "NewProcessId": "process.pid",
                    "NewProcessName": "process.executable",
                    "ParentProcessName": "process.parent.name",
                    "ProcessName": "process.executable",
                    "SourceAddress": "source.ip",
                    "TargetDomainName": "user.domain",
                    "WorkstationName": "source.domain",
                })
            ),
            ProcessingItem(         # Prepend each field that was not processed by previous field mapping transformation with "winlog.event_data."
                identifier="ecs_windows_winlog_eventdata_prefix",
                transformation=AddFieldnamePrefixTransformation("winlog.event_data."),
                detection_item_conditions=[
                    RuleProcessingItemAppliedCondition("ecs_windows_field_mapping"),
                    IncludeFieldCondition(["winlog.channel"]),
                ],
                detection_item_condition_negation=True,
                detection_item_condition_linking=any,
            )
        ],
    )