import os
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
import json
from typing import Pattern, Union
from sigma.conversion.base import TextQueryBackend, JSONQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.correlations import (
    SigmaCorrelationRule,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationTypeLiteral,
    SigmaCorrelationCondition,
    SigmaRuleReference,
)
from sigma.types import (
    SigmaCompareExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaCIDRExpression,
    SpecialChars,
)

# from sigma.pipelines.wit_elasticsearch import # TODO: add pipeline imports or delete this line
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional

file_path = os.path.abspath(__file__)


class DSLBackend(TextQueryBackend):
    """Elasticsearch DSL query language backend. Generates JSON queries described here in the Elasticsearch documentation:

    https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
    """

    name: ClassVar[str] = "Elasticsearch DSL"
    formats: Dict[str, str] = {
        "default": "Pure DSL queries",
    }
    requires_pipeline: bool = (
        False  # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    )
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[Optional[str]] = (
        None  # Expression for precedence override grouping as format string with {expr} placeholder
    )
    parenthesize: bool = (
        False  # Reflect parse tree by putting parenthesis around all expressions - use this for target systems without strict precedence rules.
    )
    # in-expressions
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[Optional[str]] = None
    and_token: ClassVar[Optional[str]] = None
    not_token: ClassVar[Optional[str]] = None
    eq_token: ClassVar[Optional[str]] = (
        None  # Token inserted between field and value (without separator)
    )
    eq_expression: ClassVar[str] = (
        '{{"term": {{ "{field}": "{value}" }} }}'  # Expression for field = value
    )
    ## Fields
    ### Quoting
    field_quote: ClassVar[Optional[str]] = (
        None  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Optional[Pattern]] = (
        None  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    )
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ### Escaping
    field_escape: ClassVar[Optional[str]] = (
        "\\"  # Character to escape particular parts defined in field_escape_pattern.
    )
    field_escape_quote: ClassVar[bool] = (
        True  # Escape quote string defined in field_quote
    )
    field_escape_pattern: ClassVar[Optional[Pattern]] = re.compile(
        "[\\s*]"
    )  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    ### String quoting
    str_quote: ClassVar[str] = (
        '"'  # string quoting character (added as escaping character)
    )
    str_quote_pattern: ClassVar[Optional[Pattern]] = re.compile(
        "."
    )  # Quote string values that match (or don't match) this pattern
    str_quote_pattern_negation: ClassVar[bool] = True  # Negate str_quote_pattern result
    ### String escaping and filtering
    escape_char: ClassVar[Optional[str]] = (
        "\\"  # Escaping character for special characters inside string
    )
    wildcard_multi: ClassVar[Optional[str]] = (
        ".*"  # Character used as multi-character wildcard
    )
    wildcard_single: ClassVar[Optional[str]] = (
        "."  # Character used as single-character wildcard
    )
    add_escaped: ClassVar[str] = (
        '+=&|!"(){}[]^~*?:\\/ '  # removed "-"  # Characters quoted in addition to wildcards and string quote
    )
    filter_chars: ClassVar[str] = ""  # Characters filtered
    ### Booleans
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "true",
            False: "false",
        }
    )

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[Optional[str]] = (
        '{{"regexp": {{ "{field}": "{value}.*", "case_insensitive": "true" }} }}'
    )
    endswith_expression: ClassVar[Optional[str]] = (
        '{{"regexp": {{ "{field}": ".*{value}", "case_insensitive": "true" }} }}'
    )
    contains_expression: ClassVar[Optional[str]] = (
        '{{"regexp": {{ "{field}": ".*{value}.*", "case_insensitive": "true" }} }}'
    )
    wildcard_match_expression: ClassVar[Optional[str]] = (
        '{{"regexp": {{ "{field}": "{value}", "case_insensitive": "true" }} }}'  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = (
        '{{"regexp": {{ "{field}": "{regex}", "case_insensitive": "true" }} }}'
    )
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ("\\",)
    # escape the escape char
    re_escape_escape_char: ClassVar[bool] = True
    re_flag_prefix: bool = (
        False  # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    )
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: {"case_insensitive": "true"}
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression: ClassVar[Optional[str]] = None
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression: ClassVar[Optional[str]] = None
    case_sensitive_endswith_expression: ClassVar[Optional[str]] = None
    case_sensitive_contains_expression: ClassVar[Optional[str]] = None

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression: ClassVar[Optional[str]] = (
        '{{ "term": {{ {field}:{network}\\/{prefixlen} }} }}'  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only)
    )

    # Numeric comparison operators
    compare_op_expression: ClassVar[Optional[str]] = (
        None  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    compare_operators: ClassVar[
        Optional[Dict[SigmaCompareExpression.CompareOperators, str]]
    ] = None  # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[Optional[str]] = (
        None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[Optional[str]] = (
        None  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    field_exists_expression: ClassVar[Optional[str]] = (
        None  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[Optional[str]] = (
        None  # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    field_in_list_expression: ClassVar[Optional[str]] = (
        None  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[Optional[str]] = (
        None  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    and_in_operator: ClassVar[Optional[str]] = (
        None  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    )
    list_separator: ClassVar[Optional[str]] = None  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[Optional[str]] = (
        None  # Expression for string value not bound to a field as format string with placeholder {value}
    )
    unbound_value_num_expression: ClassVar[Optional[str]] = (
        None  # Expression for number value not bound to a field as format string with placeholder {value}
    )
    unbound_value_re_expression: ClassVar[Optional[str]] = (
        None  # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression
    )

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[Optional[str]] = (
        None  # String used as separator between main query and deferred parts
    )
    deferred_separator: ClassVar[Optional[str]] = (
        None  # String used to join multiple deferred query parts
    )
    deferred_only_query: ClassVar[Optional[str]] = (
        None  # String used as query if final query only contains deferred expression
    )

    # Backends can offer different methods of correlation query generation. That are described by
    # correlation_methods:
    correlation_methods: ClassVar[Optional[Dict[str, str]]] = {
        "aggs": "Correlation with aggs command"
    }
    # The following class variable defines the default method that should be chosen if none is provided.
    default_correlation_method: ClassVar[str] = "aggs"

    ### Correlation rule templates
    ## Correlation query frame
    # The correlation query frame is the basic structure of a correlation query for each correlation
    # type. It contains the following placeholders:
    # * {search} is the search expression generated by the correlation query search phase.
    # * {typing} is the event typing expression generated by the correlation query typing phase.
    # * {aggregate} is the aggregation expression generated by the correlation query aggregation
    #   phase.
    # * {condition} is the condition expression generated by the correlation query condition phase.
    # If a correlation query template for a specific correlation type is not defined, the default correlation query template is used.
    default_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    event_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    value_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    temporal_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    temporal_ordered_correlation_query: ClassVar[Optional[Dict[str, str]]] = None

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "s": "seconds",
        "m": "minutes",
        "h": "hours",
        "d": "days",
        "w": "weeks",
        "M": "months",
        "y": "years",
    }
    ## Correlation query search phase
    # The first step of a correlation query is to match events described by the referred Sigma
    # rules. A main difference is made between single and multiple rule searches.
    # A single rule search expression defines the search expression emitted if only one rule is
    # referred by the correlation rule. It contains the following placeholders:
    # * {rule} is the referred Sigma rule.
    # * {ruleid} is the rule name or if not available the id of the rule.
    # * {query} is the query generated from the referred Sigma rule.
    # * {normalization} is the expression that normalizes the rule field names to unified alias
    #   field names that can be later used for aggregation. The expression is defined by
    #   correlation_search_field_normalization_expression defined below.
    correlation_search_single_rule_expression: ClassVar[Optional[str]] = "{query}"
    # If no single rule query expression is defined, the multi query template expressions below are
    # used and must be suitable for this purpose.

    # A multiple rule search expression defines the search expression emitted if multiple rules are
    # referred by the correlation rule. This is split into the expression for the query itself:
    correlation_search_multi_rule_expression: ClassVar[Optional[str]] = None
    # This template contains only one placeholder {queries} which contains the queries generated
    # from single queries joined with a query separator:
    # * A query template for each query generated from the referred Sigma rules similar to the
    #   search_single_rule_expression defined above:
    correlation_search_multi_rule_query_expression: ClassVar[Optional[str]] = (
        "({query})"
    )
    #   Usually the expression must contain some an expression that marks the matched event type as
    #   such, e.g. by using the rule name or uuid.
    # * A joiner string that is put between each search_multi_rule_query_expression:
    correlation_search_multi_rule_query_expression_joiner: ClassVar[Optional[str]] = ","

    ## Correlation query typing phase (optional)
    # Event typing expression. In some query languages the initial search query only allows basic
    # boolean expressions without the possibility to mark the matched events with a type, which is
    # especially required by temporal correlation rules to distinguish between the different matched
    # event types.
    # This is the template for the event typing expression that is used to mark the matched events.
    # It contains only a {queries} placeholder that is replaced by the result of joining
    # typing_rule_query_expression with typing_rule_query_expression_joiner defined afterwards.
    typing_expression: ClassVar[Optional[str]] = None
    # This is the template for the event typing expression for each query generated from the
    # referred Sigma rules. It contains the following placeholders:
    # * {rule} is the referred Sigma rule.
    # * {ruleid} is the rule name or if not available the id of the rule.
    # * {query} is the query generated from the referred Sigma rule.
    typing_rule_query_expression: ClassVar[Optional[str]] = None
    # String that is used to join the event typing expressions for each rule query referred by the
    # correlation rule:
    typing_rule_query_expression_joiner: ClassVar[Optional[str]] = None

    # Event field normalization expression. This is used to normalize field names in events matched
    # by the Sigma rules referred by the correlation rule. This is a dictionary mapping from
    # correlation_method names to format strings hat can contain the following placeholders:
    # * {alias} is the field name to which the event field names are normalized and that is used as
    #   group-by field in the aggregation phase.
    # * {field} is the field name from the rule that is normalized.
    # The expression is generated for each Sigma rule referred by the correlation rule and each
    # alias field definition that contains a field definition for the Sigma rule for which the
    # normalization expression is generated. All such generated expressions are joined with the
    # correlation_search_field_normalization_expression_joiner and the result is passed as
    # {normalization} to the correlation_search_*_rule_expression.
    correlation_search_field_normalization_expression: ClassVar[Optional[str]] = None
    correlation_search_field_normalization_expression_joiner: ClassVar[
        Optional[str]
    ] = None

    ## Correlation query aggregation phase
    # All of the following class variables are dictionaries of mappings from
    # correlation_method names to format strings with the following placeholders:
    # * {rule} contains the whole correlation rule object.
    # * {referenced_rules} contains the Sigma rules that are referred by the correlation rule.
    # * {field} contains the field specified in the condition.
    # * {timespan} contains the timespan converted into the target format by the convert_timespan
    #   method.
    # * {groupby} contains the group by expression generated by the groupby_* templates below.
    event_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = None
    value_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = (
        None  # Expression for value count correlation rules
    )
    temporal_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = (
        None  # Expression for temporal correlation rules
    )
    temporal_ordered_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = (
        None  # Expression for ordered temporal correlation rules
    )

    # Mapping from Sigma timespan to target format timespan specification. This can be:
    # * A dictionary mapping Sigma timespan specifications to target format timespan specifications,
    #   e.g. the Sigma timespan specifier "m" to "min".
    # * None if the target query language uses the same timespan specification as Sigma or expects
    #   seconds (see timespan_seconds) or a custom timespan conversion is implemented in the method
    #   convert_timespan.
    # The mapping can be incomplete. Non-existent timespan specifiers will be passed as-is if no
    # mapping is defined for them.
    timespan_mapping: ClassVar[Optional[Dict[str, str]]] = None
    timespan_seconds: ClassVar[bool] = (
        False  # If True, timespan is converted to seconds instead of using a more readable timespan specification like 5m.
    )

    # Expression for a referenced rule as format string with {ruleid} placeholder that is replaced
    # with the rule name or id similar to the search query expression.
    referenced_rules_expression: ClassVar[Optional[Dict[str, str]]] = None
    # All referenced rules expressions are joined with the following joiner:
    referenced_rules_expression_joiner: ClassVar[Optional[Dict[str, str]]] = None

    # The following class variables defined the templates for the group by expression.
    # First an expression frame is definied:
    groupby_expression: ClassVar[Optional[Dict[str, str]]] = None
    # This expression only contains the {fields} placeholder that is replaced by the result of
    # groupby_field_expression for each group by field joined by groupby_field_expression_joiner. The expression template
    # itself can only contain a {field} placeholder for a single field name.
    groupby_field_expression: ClassVar[Optional[Dict[str, str]]] = None
    groupby_field_expression_joiner: ClassVar[Optional[Dict[str, str]]] = None
    # Groupy by expression in the case that no fields were provided in the correlation rule:
    groupby_expression_nofield: ClassVar[Optional[Dict[str, str]]] = {None}

    ## Correlation query condition phase
    # The final correlation query phase adds a final filter that filters the aggregated events
    # according to the given conditions. The following class variables define the templates for the
    # different correlation rule types and correlation methods (dict keys).
    # Each template gets the following placeholders:
    # * {op} is the condition operator mapped according o correlation_condition_mapping.
    # * {count} is the value specified in the condition.
    # * {field} is the field specified in the condition.
    # * {referenced_rules} contains the Sigma rules that are referred by the correlation rule. This
    #   expression is generated by the referenced_rules_expression template in combincation with the
    #   referennced_rules_expression_joiner defined above.
    event_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    value_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_ordered_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    # The following mapping defines the mapping from Sigma correlation condition operators like
    # "lt", "gte" into the operatpors expected by the target query language.
    correlation_condition_mapping: ClassVar[
        Optional[Dict[SigmaCorrelationConditionOperator, str]]
    ] = {
        SigmaCorrelationConditionOperator.LT: "<",
        SigmaCorrelationConditionOperator.LTE: "<=",
        SigmaCorrelationConditionOperator.GT: ">",
        SigmaCorrelationConditionOperator.GTE: ">=",
        SigmaCorrelationConditionOperator.EQ: "==",
    }

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        index_names: List = [
            "apm-*-transaction*",
            "auditbeat-*",
            "endgame-*",
            "filebeat-*",
            "logs-*",
            "packetbeat-*",
            "traces-apm*",
            "winlogbeat-*",
            "-*elastic-cloud-logs-*",
        ],
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m",
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.index_names = index_names or [
            "apm-*-transaction*",
            "auditbeat-*",
            "endgame-*",
            "filebeat-*",
            "logs-*",
            "packetbeat-*",
            "traces-apm*",
            "winlogbeat-*",
            "-*elastic-cloud-logs-*",
        ]
        self.schedule_interval = schedule_interval or 5
        self.schedule_interval_unit = schedule_interval_unit or "m"
        self.severity_risk_mapping = {
            "INFORMATIONAL": 1,
            "LOW": 21,
            "MEDIUM": 47,
            "HIGH": 73,
            "CRITICAL": 99,
        }

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Any:
        """Conversion of AND conditions."""
        and_node = {"bool": {"must": []}}
        for arg in cond.args:
            try:
                value = self.convert_condition(arg, state)
                and_node["bool"]["must"].append(value)

            except Exception as ex:  # pragma: no cover
                raise (f"Operator 'and' not supported by the backend {ex}")
        # and_str = json.dumps(andNode)
        return and_node

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Any:
        """Conversion of NOT conditions."""
        not_node = {"bool": {"must_not": []}}
        try:
            for arg in cond.args:
                value = self.convert_condition(arg, state)
                if isinstance(value, str):
                    value = json.loads(value)
                not_node["bool"]["must_not"].append(value)

        except Exception as ex:  # pragma: no cover
            raise (f"Operator 'and' not supported by the backend {ex}")
        return not_node

    def convert_correlation_search(
        self,
        rule: SigmaCorrelationRule,
        **kwargs,
    ) -> str:
        sources = [
            state.processing_state.get("index", "*")
            for rule_reference in rule.rules
            for state in rule_reference.rule.get_conversion_states()
        ]
        if "*" in sources:
            return super().convert_correlation_search(rule, sources="*", **kwargs)
        else:
            return super().convert_correlation_search(
                rule, sources=",".join(sources), **kwargs
            )

    def convert_correlation_search_multi_rule_query_postprocess(
        self, query: str
    ) -> str:
        return query.split(" | where ")[1]

    def convert_correlation_typing_query_postprocess(self, query: str) -> str:
        return self.convert_correlation_search_multi_rule_query_postprocess(query)

    def createCIDR(self, val):
        if "*" in val:
            pass
        new = SigmaCIDRExpression()

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""

        # if all strings are case-sensitive, terms queries can be grouped.
        if all(isinstance(arg.value, SigmaCasedString) for arg in cond.args):
            in_node = {
                "terms": {self.escape_and_quote_field(cond.args[0].field): []}
            }  # The assumption that the field is the same for all argument is valid because this is checked before
            for arg in cond.args:
                to_append = ""
                if not "ip" in arg.field.lower() and isinstance(
                    arg.value, SigmaString
                ):  # string escaping and qoutingself.convert_value_str(arg.value, state)
                    to_append = self.convert_value_str(arg.value, state)
                elif "ip" in arg.field.lower():
                    to_append = str(arg.value)  # TODO !!!!

                in_node["terms"][
                    self.escape_and_quote_field(cond.args[0].field)
                ].append(to_append)
            return in_node
        else:  # if any value shall be case-INsensitive, then the values can not be searched together with 'terms' query
            in_node = {"bool": {"should": []}}
            or_nodes = []
            for arg in cond.args:
                or_nodes.append(
                    self.convert_condition_field_eq_val_str(cond=arg, state=state)
                )
            in_node["bool"]["should"] = or_nodes
            return in_node

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Any:
        """Conversion of OR conditions."""
        or_node = {"bool": {"should": []}}
        try:
            for arg in cond.args:
                value = self.convert_condition(arg, state)
                or_node["bool"]["should"].append(value)

        except Exception as ex:  # pragma: no cover
            raise (f"Operator 'and' not supported by the backend {ex}")
        return or_node

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        value = cond.value
        regex_node = {
            "regexp": {
                cond.field: {
                    "value": self.convert_value_re(value, state),
                }
            }
        }
        if not (isinstance(value, SigmaCasedString)):
            regex_node["regexp"][cond.field].update({"case_insensitive": "true"})
        return regex_node

    def field_needs_case_insensitive_search(self, field):
        if (
            self.fields_needing_case_insensitive_search
            and field in self.fields_needing_case_insensitive_search
        ):
            return True
        return False

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
            node = {"term": {self.escape_and_quote_field(cond.field): str(cond.value)}}
            return node
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals numeric value expressions are not supported by the backend."
            )

    def convert_condition_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of value-only strings."""
        return str(cond.value)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of case-sensitive field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )  # String ends with wildcard
                and not cond.value[
                    :-1
                ].contains_special()  # Remainder of string doesn't contains special characters
            ):
                value = cond.value[:-1]
                expr = {
                    "regexp": {
                        self.escape_and_quote_field(cond.field): {
                            "value": self.convert_value_str(value, state)
                            + self.wildcard_multi,
                            "case_insensitive": "false",
                        }
                    }
                }  # If all conditions are fulfilled, use 'startswith' operartor instead of equal token
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                value = cond.value[1:]
                expr = {
                    "regexp": {
                        self.escape_and_quote_field(cond.field): {
                            "value": self.wildcard_multi
                            + self.convert_value_str(value, state),
                            "case_insensitive": "false",
                        }
                    }
                }
            elif (  # contains: string starts and ends with wildcard
                cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                value = cond.value[1:-1]
                expr = {
                    "regexp": {
                        self.escape_and_quote_field(cond.field): {
                            "value": self.wildcard_multi
                            + self.convert_value_str(value, state)
                            + self.wildcard_multi,
                            "case_insensitive": "false",
                        }
                    }
                }
            else:
                value = cond.value
                original_value = value.original
                expr = {
                    "term": {self.escape_and_quote_field(cond.field): original_value}
                }  # is case sensitive by default
            return expr
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Case-sensitive field equals string value expressions with strings are not supported by the backend."
            )

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )  # String ends with wildcard
                and not cond.value[
                    :-1
                ].contains_special()  # Remainder of string doesn't contains special characters
            ):
                value = cond.value[:-1]
                expr = {
                    "regexp": {
                        self.escape_and_quote_field(cond.field): {
                            "value": self.convert_value_str(value, state)
                            + self.wildcard_multi,
                            "case_insensitive": "true",
                        }
                    }
                }  # If all conditions are fulfilled, use 'startswith' operartor instead of equal token
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                value = cond.value[1:]
                expr = {
                    "regexp": {
                        self.escape_and_quote_field(cond.field): {
                            "value": self.wildcard_multi
                            + self.convert_value_str(value, state),
                            "case_insensitive": "true",
                        }
                    }
                }
            elif (  # contains: string starts and ends with wildcard
                cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                value = cond.value[1:-1]
                expr = {
                    "regexp": {
                        self.escape_and_quote_field(cond.field): {
                            "value": self.wildcard_multi
                            + self.convert_value_str(value, state)
                            + self.wildcard_multi,
                            "case_insensitive": "true",
                        }
                    }
                }
            elif (  # wildcard match expression: string contains wildcard
                cond.value.contains_special()
            ):
                value = cond.value
                expr = {
                    "regexp": {
                        self.escape_and_quote_field(cond.field): {
                            "value": self.convert_value_str(value, state),
                            "case_insensitive": "true",
                        }
                    },
                }
            else:  # equals --> exact match but case insensitive (Works on Keyword fields with Elastic >= 7.10)
                value = cond.value
                original_value = value.original
                expr = {
                    "term": {
                        self.escape_and_quote_field(cond.field): {
                            "value": original_value,
                            "case_insensitive": "true",
                        }
                    }
                }
            return expr
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        query = {"query": {"constant_score": {"filter": query}}}
        return query

    def finalize_output_default(self, queries: List[str]) -> Any:
        # TODO: implement the output finalization for all generated queries for the format {{ format }} here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        # TODO: proper type annotation. Sigma CLI supports:
        # - str: output as is.
        # - bytes: output in file only (e.g. if a zip package is output).
        # - dict: output serialized as JSON.
        # - list of str: output each item as is separated by two newlines.
        # - list of dict: serialize each item as JSON and output all separated by newlines.
        return list(queries)

    # Correlation query conversion
    # The following methods are used to convert Sigma correlation rules into queries. The conversion
    # starts with the convert_correlation_rule method that calls correlation type specific methods
    # which itself call convert_correlation_rule_from_template that dispatches to the three
    # correlation query phases: search, aggregation and condition.
    def convert_correlation_rule_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
    ) -> str:
        try:
            field_to_agg_by: str = rule.group_by[0]
        except Exception as ex:
            print(f"Currently only one Field is supported to be aggregated by; {ex}")
            field_to_agg_by = None

        grouped_name = field_to_agg_by.replace(".", "_")
        if correlation_type == "value_count" and rule.condition.fieldref:
            agg_func = "cardinality"
            agg_field = rule.condition.fieldref
            agg_name = f"card({field_to_agg_by.replace('.', '_')})"
        else:
            agg_func = "value_count"
            agg_field = field_to_agg_by
            agg_name = f"count({grouped_name})"
        script_limit = f"params.count {self.correlation_condition_mapping.get(rule.condition.op)} {rule.condition.count}"
        query = self.convert_correlation_search(rule)
        query["aggs"] = {
            "group_aggregation": {
                "composite": {
                    "size": 20,
                    "sources": [{grouped_name: {"terms": {"field": field_to_agg_by}}}],
                },
                "aggs": {
                    agg_name: {agg_func: {"field": agg_field}},
                    "limit": {
                        "bucket_selector": {
                            "buckets_path": {"count": agg_name},
                            "script": script_limit,
                        }
                    },
                },
            }
        }
        return [query]

    # Implementation of the search phase of the correlation query.
    def convert_correlation_search(
        self,
        rule: SigmaCorrelationRule,
        **kwargs,
    ) -> str:
        if (  # if the correlation rule refers only a single rule and this rule results only in a single query
            len(rule.rules) == 1
            and len(
                queries := (
                    rule_reference := rule.rules[0].rule
                ).get_conversion_result()
            )
            == 1
            and self.correlation_search_single_rule_expression is not None
        ):
            return queries[0]
        else:
            return self.correlation_search_multi_rule_expression.format(
                queries=self.correlation_search_multi_rule_query_expression_joiner.join(
                    (
                        self.correlation_search_multi_rule_query_expression.format(
                            rule=rule_reference.rule,
                            ruleid=rule_reference.rule.name or rule_reference.rule.id,
                            query=self.convert_correlation_search_multi_rule_query_postprocess(
                                query
                            ),
                            normalization=self.convert_correlation_search_field_normalization_expression(
                                rule.aliases,
                                rule_reference,
                            ),
                        )
                        for rule_reference in rule.rules
                        for query in rule_reference.rule.get_conversion_result()
                    )
                ),
                **kwargs,
            )

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Union[str, DeferredQueryExpression],
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Union[str, DeferredQueryExpression]:
        """
        Finalize query by appending deferred query parts to the main conversion result as specified
        with deferred_start and deferred_separator.
        """
        # TODO when Python 3.8 is dropped: replace ChainMap with | operator.
        conversion_state = ChainMap(state.processing_state, self.state_defaults)

        if state.has_deferred():
            if isinstance(query, DeferredQueryExpression):
                query = self.deferred_only_query
            return super().finalize_query(
                rule,
                self.query_expression.format(
                    query=query,
                    rule=rule,
                    state=conversion_state,
                )
                + self.deferred_start
                + self.deferred_separator.join(
                    (
                        deferred_expression.finalize_expression()
                        for deferred_expression in state.deferred
                    )
                ),
                index,
                state,
                output_format,
            )
        else:
            # use 'Backend' base class, not 'TextQueryBackend'
            res = super(TextQueryBackend, self).finalize_query(
                rule,
                query,
                index,
                state,
                output_format,
            )
            return res
