@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        'PSAvoidUsingPositionalParameters'
        'PSUseDeclaredVarsMoreThanAssignments'
        'PSUseSingularNouns'
        'PSAvoidUsingWriteHost'
        'PSReviewUnusedParameter'
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
