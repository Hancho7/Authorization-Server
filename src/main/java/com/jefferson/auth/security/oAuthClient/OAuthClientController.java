package com.jefferson.auth.security.oAuthClient;

import com.jefferson.auth.commons.ApiResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/admin/oauth-clients")
@PreAuthorize("hasRole('ADMIN')")
public class OAuthClientController {

    private final OAuthClientService oAuthClientService;

    public OAuthClientController(OAuthClientService oAuthClientService) {
        this.oAuthClientService = oAuthClientService;
    }

    @GetMapping
    public ApiResponse<Page<OAuthClientEntity>> getAllClients(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size);
        Page<OAuthClientEntity> clients = oAuthClientService.getAllClients(pageable);
        return ApiResponse.response("Clients retrieved successfully", clients, 200);
    }

    @GetMapping("/{id}")
    public ApiResponse<OAuthClientEntity> getClientById(@PathVariable String id) {
        Optional<OAuthClientEntity> client = oAuthClientService.getClientById(id);
        return client.map(oAuthClientEntity -> ApiResponse.response("Client retrieved successfully", oAuthClientEntity, 200)).orElseGet(() -> ApiResponse.response("Client not found", null, 404));
    }

    @GetMapping("/by-client-id/{clientId}")
    public ApiResponse<OAuthClientEntity> getClientByClientId(@PathVariable String clientId) {
        OAuthClientEntity client = oAuthClientService.getClientByClientId(clientId);
        return ApiResponse.response("Client retrieved successfully", client, 200);
    }

    @PostMapping
    public ApiResponse<OAuthClientEntity> createClient(@Valid @RequestBody OAuthClientService.CreateClientRequest request) {
        OAuthClientEntity createdClient = oAuthClientService.createClient(request);
        return ApiResponse.response("Client created successfully", createdClient, 201);
    }

    @PutMapping("/{id}")
    public ApiResponse<OAuthClientEntity> updateClient(@PathVariable String id,
                                                       @Valid @RequestBody OAuthClientService.UpdateClientRequest request) {
        OAuthClientEntity updatedClient = oAuthClientService.updateClient(id, request);
        return ApiResponse.response("Client updated successfully", updatedClient, 200);
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> deleteClient(@PathVariable String id) {
        oAuthClientService.deleteClient(id);
        return ApiResponse.response("Client deleted successfully", null, 204);
    }

    @GetMapping("/search")
    public ApiResponse<List<OAuthClientEntity>> searchClients(
            @RequestParam(required = false) String clientName,
            @RequestParam(required = false) String clientId) {

        List<OAuthClientEntity> clients = oAuthClientService.searchClients(clientName, clientId);
        return ApiResponse.response("Search completed successfully", clients, 200);
    }
}