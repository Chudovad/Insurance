using Insurance.Domain.Models;
using MudBlazor;
using System.ComponentModel.DataAnnotations;

namespace Insurance.MiniApp.Components.Pages
{
    public partial class Profile
    {
        private bool _isLoading = true;
        private bool _isChangingPassword = false;

        // Поля для формы изменения пароля
        private ChangePasswordModel _changePasswordModel = new();
        private bool _showCurrentPassword = false;
        private bool _showNewPassword = false;
        private bool _showConfirmNewPassword = false;
        private InputType _currentPasswordInput = InputType.Password;
        private InputType _newPasswordInput = InputType.Password;
        private InputType _confirmNewPasswordInput = InputType.Password;
        private string _currentPasswordError = string.Empty;
        private string _newPasswordError = string.Empty;
        private string _confirmNewPasswordError = string.Empty;

        protected override async Task OnAfterRenderAsync(bool firstRender)
        {
            if (firstRender)
            {
                var isAuthenticated = await AuthService.IsAuthenticatedAsync();

                if (!isAuthenticated)
                {
                    Navigation.NavigateTo("/login");
                    return;
                }

                await Task.Delay(800);
                _isLoading = false;
                StateHasChanged();
            }
        }

        private void ToggleCurrentPasswordVisibility()
        {
            _showCurrentPassword = !_showCurrentPassword;
            _currentPasswordInput = _showCurrentPassword ? InputType.Text : InputType.Password;
        }

        private void ToggleNewPasswordVisibility()
        {
            _showNewPassword = !_showNewPassword;
            _newPasswordInput = _showNewPassword ? InputType.Text : InputType.Password;
        }

        private void ToggleConfirmNewPasswordVisibility()
        {
            _showConfirmNewPassword = !_showConfirmNewPassword;
            _confirmNewPasswordInput = _showConfirmNewPassword ? InputType.Text : InputType.Password;
        }

        private async Task HandleChangePassword()
        {
            _currentPasswordError = string.Empty;
            _newPasswordError = string.Empty;
            _confirmNewPasswordError = string.Empty;

            // Валидация паролей
            if (_changePasswordModel.NewPassword != _changePasswordModel.ConfirmNewPassword)
            {
                _confirmNewPasswordError = "Пароли не совпадают";
                StateHasChanged();
                return;
            }

            if (_changePasswordModel.NewPassword.Length < 6)
            {
                _newPasswordError = "Пароль должен содержать минимум 6 символов";
                StateHasChanged();
                return;
            }

            if (_changePasswordModel.CurrentPassword == _changePasswordModel.NewPassword)
            {
                _newPasswordError = "Новый пароль должен отличаться от текущего";
                StateHasChanged();
                return;
            }

            _isChangingPassword = true;
            StateHasChanged();

            try
            {
                var request = new ChangePasswordRequest
                {
                    CurrentPassword = _changePasswordModel.CurrentPassword,
                    NewPassword = _changePasswordModel.NewPassword
                };

                var result = await AuthService.ChangePasswordAsync(request);

                if (result.IsSuccess)
                {
                    Snackbar.Add("Пароль успешно изменен", Severity.Success);

                    // Очистка формы
                    _changePasswordModel = new ChangePasswordModel();
                    _currentPasswordInput = InputType.Password;
                    _newPasswordInput = InputType.Password;
                    _confirmNewPasswordInput = InputType.Password;
                    _showCurrentPassword = false;
                    _showNewPassword = false;
                    _showConfirmNewPassword = false;
                }
                else
                {
                    // Обработка ошибок от API
                    if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        _currentPasswordError = result.ErrorMessage ?? "Неверный текущий пароль";
                    }
                    else if (result.StatusCode == System.Net.HttpStatusCode.BadRequest)
                    {
                        var errorMessage = result.ErrorMessage ?? "Ошибка валидации";
                        if (errorMessage.Contains("минимум"))
                        {
                            _newPasswordError = errorMessage;
                        }
                        else if (errorMessage.Contains("отличаться"))
                        {
                            _newPasswordError = errorMessage;
                        }
                        else
                        {
                            _newPasswordError = errorMessage;
                        }
                    }
                    else
                    {
                        Snackbar.Add(result.ErrorMessage ?? "Ошибка при изменении пароля", Severity.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                Snackbar.Add($"Неожиданная ошибка: {ex.Message}", Severity.Error);
            }
            finally
            {
                _isChangingPassword = false;
                StateHasChanged();
            }
        }

        public class ChangePasswordModel
        {
            [Required(ErrorMessage = "Текущий пароль обязателен")]
            public string CurrentPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "Новый пароль обязателен")]
            [MinLength(6, ErrorMessage = "Пароль должен содержать минимум 6 символов")]
            public string NewPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "Подтверждение пароля обязательно")]
            public string ConfirmNewPassword { get; set; } = string.Empty;
        }
    }
}
