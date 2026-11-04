package takagi.ru.monica.cloud.api

import okhttp3.RequestBody
import okhttp3.ResponseBody
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query
import retrofit2.http.Streaming

/** Retrofit binding of protocol §4. Base URL is `{serverUrl}/api/v1/`. */
interface MonicaCloudApi {
    @GET("config")
    suspend fun config(): ServerConfigDto

    @POST("accounts/prelogin")
    suspend fun prelogin(@Body body: PreloginRequest): PreloginResponse

    @POST("accounts/register")
    suspend fun register(@Body body: RegisterRequest): RegisterResponse

    @POST("auth/token")
    suspend fun token(@Body body: TokenRequest): TokenResponse

    @POST("auth/logout")
    suspend fun logout(@Body body: EmptyBody = EmptyBody())

    @GET("accounts/profile")
    suspend fun profile(): ProfileDto

    @GET("accounts/revision-date")
    suspend fun revisionDate(): RevisionDateResponse

    @GET("sync")
    suspend fun sync(@Query("since") since: String? = null): SyncResponse

    @POST("items")
    suspend fun createItem(@Body body: ItemWriteRequest): ItemDto

    @POST("items/import")
    suspend fun importItems(@Body body: ImportRequest): ImportResponse

    @POST("items/bulk")
    suspend fun bulk(@Body body: BulkRequest): BulkResponse

    @GET("items/{id}")
    suspend fun getItem(@Path("id") id: String): ItemDto

    @PUT("items/{id}")
    suspend fun updateItem(@Path("id") id: String, @Body body: ItemWriteRequest): ItemDto

    @POST("items/{id}/trash")
    suspend fun trashItem(@Path("id") id: String, @Body body: EmptyBody = EmptyBody()): ItemDto

    @POST("items/{id}/restore")
    suspend fun restoreItem(@Path("id") id: String, @Body body: EmptyBody = EmptyBody()): ItemDto

    @DELETE("items/{id}")
    suspend fun deleteItem(@Path("id") id: String): EmptyBody

    @POST("folders")
    suspend fun createFolder(@Body body: FolderWriteRequest): FolderDto

    @PUT("folders/{id}")
    suspend fun updateFolder(@Path("id") id: String, @Body body: FolderWriteRequest): FolderDto

    @DELETE("folders/{id}")
    suspend fun deleteFolder(@Path("id") id: String): EmptyBody

    @POST("items/{id}/attachments")
    suspend fun registerAttachment(@Path("id") itemId: String, @Body body: AttachmentRegisterRequest): AttachmentRegisterResponse

    @PUT("items/{id}/attachments/{aid}")
    suspend fun uploadAttachment(@Path("id") itemId: String, @Path("aid") attachmentId: String, @Body body: RequestBody): ItemDto

    @Streaming
    @GET("items/{id}/attachments/{aid}")
    suspend fun downloadAttachment(@Path("id") itemId: String, @Path("aid") attachmentId: String): ResponseBody

    @DELETE("items/{id}/attachments/{aid}")
    suspend fun deleteAttachment(@Path("id") itemId: String, @Path("aid") attachmentId: String): ItemDto
}
