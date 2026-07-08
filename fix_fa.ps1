Get-ChildItem -Path "\\wsl$\Ubuntu\home\mahdi\projects\secpath-radar\src\intel\*.rs" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    $content = $content -replace '"summary_fa"', '"summary"'
    $content = $content -replace '"title_fa"', '"title"'
    $content = $content -replace '"label_fa"', '"label"'
    $content = $content -replace '"date_fa"', '"date_en"'
    $content = $content -replace 'summary_fa', 'summary'
    $content = $content -replace 'title_fa', 'title'
    $content = $content -replace 'label_fa', 'label'
    $content = $content -replace 'date_fa', 'date_en'
    Set-Content -Path $_.FullName -Value $content -NoNewline
}

Get-ChildItem -Path "\\wsl$\Ubuntu\home\mahdi\projects\secpath-radar\src\*.rs" -File | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    $content = $content -replace '"summary_fa"', '"summary"'
    $content = $content -replace '"title_fa"', '"title"'
    $content = $content -replace '"label_fa"', '"label"'
    $content = $content -replace '"date_fa"', '"date_en"'
    $content = $content -replace 'summary_fa', 'summary'
    $content = $content -replace 'title_fa', 'title'
    $content = $content -replace 'label_fa', 'label'
    $content = $content -replace 'date_fa', 'date_en'
    Set-Content -Path $_.FullName -Value $content -NoNewline
}
